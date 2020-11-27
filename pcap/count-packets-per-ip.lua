#!/usr/bin/env dnsjit

-- count-packets-per-ip.lua: provide packet summary for every source IP

local input = require("dnsjit.input.pcap").new()
local layer = require("dnsjit.filter.layer").new()
local object = require("dnsjit.core.objects")
local log = require("dnsjit.core.log").new("count-packets-per-ip.lua")
local getopt = require("dnsjit.lib.getopt").new({
	{ "r", "read", "", "input file to read", "?" },
	{ nil, "csv", "", "path to the output CSV file (default: stdout)", "?" },
})

log:enable("all")

-- Parse arguments
local args = {}
getopt:parse()
args.read = getopt:val("r")
args.csv = getopt:val("csv")

-- Display help
if getopt:val("help") then
	getopt:usage()
	return
end

-- Set up input
if args.read ~= "" then
	if input:open_offline(args.read) ~= 0 then
		log:fatal("failed to open input PCAP "..args.read)
	end
	log:notice("using input PCAP "..args.read)
else
	getopt:usage()
	log:fatal("input must be specified, use -r")
end
layer:producer(input)
local produce, pctx = layer:produce()

-- Set up CSV
local csv_output
if args.csv ~= "" then
	csv_output = io.open(args.csv, 'w')
	if csv_output == nil then
		log:fatal('failed to open "'..args.csv..'" for writing')
	else
		log:notice('writing output CSV to "'..args.csv..'"')
	end
else
	csv_output = io.stdout
end

local clients = {}
local now_ms, chunk_since_ms
local n_clients = 0

log:info("processing... (this may take up to minutes for very large files)")
local obj, obj_pcap_in, obj_ip, client, src_ip
while true do
	obj = produce(pctx)
	if obj == nil then break end

	obj_ip = obj:cast_to(object.IP)
	if obj_ip == nil then
		obj_ip = obj:cast_to(object.IP6)
	end

	obj_pcap_in = obj:cast_to(object.PCAP)
	if obj_ip ~= nil and obj_pcap_in ~= nil then
		now_ms = tonumber(obj_pcap_in.ts.sec) * 1e3 + tonumber(obj_pcap_in.ts.nsec) * 1e-6
		if chunk_since_ms == nil then
			chunk_since_ms = now_ms
		end

		src_ip = obj_ip:source()
		client = clients[src_ip]
		if client == nil then
			client = {
				packets = 0,
				since_ms = now_ms,
				until_ms = now_ms,
			}
			clients[src_ip] = client
			n_clients = n_clients + 1
		end
		client["packets"] = client["packets"] + 1
		client["until_ms"] = now_ms
	end
end

local duration_s = (now_ms - chunk_since_ms) / 1e3
log:info(string.format("duration of input PCAP (s): %.3f", duration_s))
log:info(string.format("number of clients: %d", n_clients))

csv_output:write("ip,ip_since_ms,ip_until_ms,packets,ip_chunk_qps\n")
local format = '"%s",%d,%d,%d,%.2f\n'
for ip, data in pairs(clients) do
	csv_output:write(string.format(
		format,
		ip,
		data["since_ms"],
		data["until_ms"],
		data["packets"],
		data["packets"] / duration_s
	))
end
csv_output:close()
