#!/usr/bin/env dnsjit

-- filter-dnsq.lua: obtain DNS queries from input PCAP / interface
--
-- Process input and extract DNS queries into an output PCAP.

local input = require("dnsjit.input.pcap").new()
local output = require("dnsjit.output.pcap").new()
local layer = require("dnsjit.filter.layer").new()
local object = require("dnsjit.core.objects")
local dns = require("dnsjit.core.object.dns").new()
local dns_q = require("dnsjit.core.object.dns.q").new()
local dns_rr = require("dnsjit.core.object.dns.rr").new()
local labels = require("dnsjit.core.object.dns.label").new(127)
local log = require("dnsjit.core.log").new("filter-dnsq.lua")
local getopt = require("dnsjit.lib.getopt").new({
	{ "r", "read", "", "input file to read", "?" },
	{ "i", "interface", "", "capture interface", "?" },
	{ "w", "write", "", "output file to write", "?" },
	{ "p", "port", 53, "destination port to check for UDP DNS queries", "?" },
	{ "m", "malformed", false, "include malformed queries", "?" },
	{ "", "csv", "time_s,period_time_since_ms,period_time_until_ms,period_queries,total_queries,period_qps,total_qps",
		"format of output CSV (header)", "?" },
	{ "s", "stats_period", 100, "period for printing stats (ms)", "?" },
})

log:enable("all")

-- Parse arguments
local args = {}
getopt:parse()
args.read = getopt:val("r")
args.interface = getopt:val("i")
args.write = getopt:val("w")
args.port = getopt:val("p")
args.malformed = getopt:val("m")
args.csv = getopt:val("csv")
args.stats_period = getopt:val("s")

-- Display help
if getopt:val("help") then
	getopt:usage()
	return
end

-- Check arguments
if args.port <= 0 or args.port > 65535 then
	log:fatal("invalid port number")
end
if args.stats_period <= 0 then
	log:fatal("stats_period must be grater than 0")
end

-- Set up input
if args.read ~= "" then
	if input:open_offline(args.read) ~= 0 then
		log:fatal("failed to open input PCAP "..args.read)
	end
	log:notice("using input PCAP "..args.read)
elseif args.interface ~= "" then
	input:create(args.interface)
	if input:activate() ~= 0 then
		log:fatal("failed to capture interface "..args.interface.." (insufficient permissions?)")
	end
	log:notice("capturing input interface "..args.interface)
else
	getopt:usage()
	log:fatal("input must be specified, use -r/-i")
end
layer:producer(input)
local produce, pctx = layer:produce()

-- Set up output
if args.write == "" then
	output = require("dnsjit.output.null").new()
elseif output:open(args.write, input:linktype(), input:snaplen()) ~= 0 then
	log:fatal("failed to open output PCAP "..args.write)
else
	log:notice("using output PCAP "..args.write)
end
local write, writectx = output:receive()

-- Set up statistics
local csv_output = nil
if args.csv ~= "" then
	csv_output = io.stdout
end
local stats = require("qstats").new(args.stats_period, csv_output, args.csv)

-- Filtering function that picks only DNS queries
local function is_dnsq(obj)
	local payload = obj:cast_to(object.PAYLOAD)
	if payload == nil then return false end
	if payload.len < 12 then return false end  -- ignore garbage smaller than DNS header size
	local udp = obj:cast_to(object.UDP)
	if udp == nil then return false end  -- use only UDP packets
	if udp.dport ~= args.port then return false end
	dns.obj_prev = obj
	dns:parse_header()
	if dns.qr == 1 then return false end  -- ignore DNS responses
	if args.malformed then return true end
	-- check that query isn't malformed
	if dns.qdcount > 0 then  -- parse all questions
		for _ = 1, dns.qdcount do
			if dns:parse_q(dns_q, labels, 127) ~= 0 then return false end
		end
	end
	local rrcount = dns.ancount + dns.nscount + dns.arcount
	if rrcount > 0 then  -- parse all other RRs
		for _ = 1, rrcount do
			if dns:parse_rr(dns_rr, labels, 127) ~= 0 then return false end
		end
	end
	return true
end

local obj
while true do
	obj = produce(pctx)
	if obj == nil then break end
	if is_dnsq(obj) then
		write(writectx, obj)
		stats:receive(obj)
	end
end
stats:finish()

if args.write ~= "" then
	output:close()
end
