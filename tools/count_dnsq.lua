#!/usr/bin/env dnsjit
--
-- count_dnsq.lua: count number of valid udp dns queries in pcap / on interface
--
-- Count the number of dns queries in given interval and print the value on stdout.
-- Only UDP DNS queries on given port that aren't malformed are counted.
--
-- If input PCAP is set, reads and processes the entire PCAP and quits.
-- If interface is set, packets from that interface are counted until program is stopped.
--

local object = require("dnsjit.core.objects")
local input = require("dnsjit.input.pcap").new()
local layer = require("dnsjit.filter.layer").new()
local dns = require("dnsjit.core.object.dns").new()
local log = require("dnsjit.core.log").new("count_dnsq")
local getopt = require("dnsjit.lib.getopt").new({
	{ "f", "file", "", "input PCAP", "?" },
	{ "i", "interface", "", "capture interface", "?" },
	{ "I", "interval", 100, "interval for counting queries (in ms)", "?" },
	{ "p", "port", 53, "port to capture", "?" }
})

getopt:parse()
local pcap = getopt:val("f")
local interface = getopt:val("i")
local interval = getopt:val("I")
local port = getopt:val("p")

if pcap ~= "" then
	input:open_offline(pcap)
elseif interface ~= "" then
	input:create(interface)
	if input:activate() ~= 0 then
		log:fatal("failed to capture interface "..interface.." (insufficient permissions?)")
	end
else
	log:fatal("pcap (-f) or interface (-i) must be set")
end
layer:producer(input)
local produce, pctx = layer:produce()

local until_ms = nil
local qcount = 0
local function inc_qcount(ms)
	if until_ms == nil then
		until_ms = ms + interval
	end
	while ms >= until_ms do
		print(qcount)
		qcount = 0
		until_ms = until_ms + interval
	end
	qcount = qcount + 1
end

while true do
	local obj = produce(pctx)
	if obj == nil then break end

	local obj_udp = obj:cast_to(object.UDP)
	local obj_pcap = obj:cast_to(object.PCAP)

	local ts
	if obj_pcap ~= nil then
		ts = obj_pcap.ts
	end
	local ms = ts.sec * 1000 + ts.nsec / 1000000

	dns.obj_prev = obj
	if obj_udp ~= nil and obj_udp.dport == port and dns:parse(256) == 0 and dns.qr == 0 then
		inc_qcount(ms)
	end
end

inc_qcount(interval)  -- ensure the last value is printed out
