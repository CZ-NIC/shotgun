#!/usr/bin/env dnsjit

-- filter-dnsq.lua: obtain DNS queries from input PCAP / interface
--
-- Process input and extract DNS queries into an output PCAP.

local ffi = require("ffi")
local C = ffi.C
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
	{ "w", "write", "", "output file to write (or /dev/null)", "?" },
	{ "p", "port", 53, "destination port to check for UDP DNS queries", "?" },
	{ "l", "log-malformed", false, "log why queries were considered as malformed", "?" },
	{ "m", "malformed", false, "include malformed queries", "?" },
	{ "M", "only-malformed", false, "include only malformed queries", "?" },
	{ "s", "skipped", false, "include queries for *.dotnxdomain.net, "
				 .. "which would otherwise be skipped", "?" },
	{ "a", "address", "", "destination address (can be specified multiple times)", "?*" },
})

local AF_INET = 2
local AF_INET6 = 10
if ffi.os == "OSX" then
    AF_INET6 = 30
end

local args

local function check_output()
	if output:have_errors() then
		log:fatal("error writting to file %s", args.write)
	end
end

ffi.cdef[[
    int inet_pton(int af, const char* src, void* dst);
    int memcmp(const void *s1, const void *s2, size_t n);
]]

log:enable("all")

-- Parse arguments
args = {}
getopt:parse()
args.read = getopt:val("r")
args.interface = getopt:val("i")
args.write = getopt:val("w")
args.port = getopt:val("p")
args.only_malformed = getopt:val("M")
args.malformed = getopt:val("m") or args.only_malformed
args.log_malformed = getopt:val("l")
args.csv = getopt:val("csv")
args.skipped = getopt:val("s")
args.address = getopt:val("a")

-- Display help
if getopt:val("help") then
	getopt:usage()
	return
end

-- Check arguments
if args.port <= 0 or args.port > 65535 then
	log:fatal("invalid port number")
end

-- Convert IPs to binary
local addresses = {}
if #args.address > 0 then
	for i, addr in ipairs(args.address) do
		local inet = ffi.new("uint8_t [16]")  -- reserve enough memory for either IPv4 or IPv6
		local len = 4
		-- try parse as IPv4
		if C.inet_pton(AF_INET, addr, inet) ~= 1 then
			len = 16
			if C.inet_pton(AF_INET6, addr, inet) ~= 1 then
				log:fatal("failed to parse address as IPv4 or IPv6: "..addr)
			end
		end
		addresses[i] = { inet = inet, len = len }
	end
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
	log:fatal("output must be specified, use -w; use /dev/null if you want just counters")
elseif output:open(args.write, input:linktype(), input:snaplen()) ~= 0 then
	log:fatal("failed to open output PCAP "..args.write)
else
	log:notice("using output PCAP "..args.write)
end
local write, writectx = output:receive()

local function matches_addresses(ip, len)
	for _, addr in ipairs(addresses) do
		if addr.len == len and C.memcmp(ip, addr.inet, len) == 0 then
			return true
		end
	end
	return false
end

local function rr_idx_section_name(rr_idx, ancount, nscount)
	if rr_idx <= ancount then
		return string.format('answer RR idx %d', rr_idx)
	elseif rr_idx <= ancount + nscount then
		return string.format('authority RR idx %d', rr_idx - ancount)
	else
		return string.format('additional RR idx %d', rr_idx - ancount - nscount)
	end
end

local function log_packet(obj, reason)
	if not args.log_malformed then
		return
	end
	local obj_pcap = obj:cast_to(object.PCAP)
	log:info("timestamp %d.%d: %s", obj_pcap.ts.sec, obj_pcap.ts.nsec, reason)
end

local function is_skipped_qname(payload, qlabels, max_labels)
	local found_labels = 0
	-- iterate over label lengths to the or label array end
	for n = 1, max_labels do
		local qlabel = qlabels[n - 1]
		if qlabel.have_offset == 1 then
			return nil -- malformed, qname should not be compressed
		elseif qlabel.have_dn == 0 then
			break  -- end of label array
		end
		-- have_dn == 1, continue to see if there are further labels
		found_labels = n
	end
	-- check if qname can have form *.dotnxdomain.net.
	if found_labels < 3 then
		return false
	end
	-- malformed, qname must be terminated with root label
	if qlabels[found_labels].length ~= 0 then
		return nil
	end

	-- is it in net.?
	local tld = qlabels[found_labels - 1]
	if tld.length ~= 3 then
		return false
	end
	local tlddata = ffi.cast('char *', payload + tld.offset + 1)
	if ffi.string(tlddata, tld.length):lower() ~= 'net' then
		return false
	end

	-- is it in dotnxdomain.net.?
	local sld = qlabels[found_labels - 2]
	if sld.length ~= 11 then
		return false
	end
	local slddata = ffi.cast('char *', payload + sld.offset + 1)
	if ffi.string(slddata, sld.length):lower() ~= 'dotnxdomain' then
		return false
	end

	return true
end


local nmalformed = 0
local nskipped = 0
-- Filtering function that picks only DNS queries
local function is_dnsq(obj)
	local payload = obj:cast_to(object.PAYLOAD)
	if payload == nil then return false end
	if payload.len < 12 then return false end  -- ignore garbage smaller than DNS header size
	local udp = obj:cast_to(object.UDP)
	if udp == nil then return false end  -- use only UDP packets
	if udp.dport ~= args.port then return false end

	if #addresses > 0 then  -- check destination IP
		local ip_obj = obj:cast_to(object.IP) or obj:cast_to(object.IP6)
		local len = 4
		if ip_obj.obj_type == object.IP6 then len = 16 end
		if matches_addresses(ip_obj.dst, len) == false then return false end
	end

	dns:reset()
	dns.obj_prev = obj
	dns:parse_header()
	if dns.qr == 1 then return false end  -- ignore DNS responses

	-- check that query isn't malformed
	if dns.qdcount > 0 then  -- parse all questions
		for idx = 1, dns.qdcount do
			if dns:parse_q(dns_q, labels, 127) ~= 0 then
				log_packet(obj, string.format('cannot parse qname idx %d', idx))
				nmalformed = nmalformed + 1
				return args.malformed
			end
			local is_skipped = is_skipped_qname(dns.payload, labels, 127)
			if is_skipped == nil then
				log_packet(obj, string.format('too suspicious qname idx %d', idx))
				nmalformed = nmalformed + 1
				return args.malformed
			elseif is_skipped and not args.skipped then
				nskipped = nskipped + 1
				return false
			end
		end
	end
	local rrcount = dns.ancount + dns.nscount + dns.arcount
	if rrcount > 0 then  -- parse all other RRs
		for idx = 1, rrcount do
			if dns:parse_rr(dns_rr, labels, 127) ~= 0 then
				log_packet(obj, string.format('malformed RR idx %d (%s)', idx, rr_idx_section_name(idx, dns.ancount, dns.nscount)))
				nmalformed = nmalformed + 1
				return args.malformed
			end
		end
	end
	return not args.only_malformed
end

local npackets_in = 0
local npackets_out = 0
local obj
while true do
	obj = produce(pctx)
	if obj == nil then break end
	npackets_in = npackets_in + 1
	if is_dnsq(obj) then
		write(writectx, obj)
		npackets_out = npackets_out + 1
		if npackets_out % 10000 == 0 then
			check_output()
		end
	end
end

check_output()
output:close()

if npackets_out == 0 then
	log:fatal("no packets were matched by filter!")
else
	log:notice("%0.f out of %0.f packets matched filter (%f %%)",
		npackets_out, npackets_in, npackets_out / npackets_in * 100)
	if nmalformed > 0 then
		local total
		if args.only_malformed then
			total = npackets_out
		else
			total = npackets_out + nmalformed
		end
		local malformed_desc
		if args.malformed then
			malformed_desc = "and written to output"
		else
			malformed_desc = "and omitted from output"
		end
		log:notice("%0.f malformed DNS packets detected "
				.. "(%f %% of matching packets) %s",
			nmalformed, nmalformed / total * 100, malformed_desc)
	else
		log:info("0 malformed DNS packets detected")
	end
	if nskipped > 0 then
		log:notice("%0.f skipped queries for *.dotnxdomain.net were "
			   .. "omitted from output", nskipped)
	end
end
