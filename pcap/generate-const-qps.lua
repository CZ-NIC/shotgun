#!/usr/bin/env dnsjit
local bit = require("bit")

-- For mysterious reasons this combination of write_uint32 implementations is fastest
-- with QPS >= 10 and it gets only slower if implementations are unified (LuaJIT 2.1.0b3).
-- It is slower for QPS < 10 but that's a corner case we are not optimizing for.
local function write_uint32_le(output, src)
	local s = string.char(
		bit.band(src, 0xff),
		bit.rshift(bit.band(src, 0xff00), 8),
		bit.rshift(bit.band(src, 0xff0000), 16),
		bit.rshift(bit.band(src, 0xff000000), 24))
	output:write(s)
	return s
end

local function write_uint32_be(output, src)
	output:write(string.char(
		bit.rshift(bit.band(src, 0xff000000), 24)))
	output:write(string.char(
		bit.rshift(bit.band(src, 0xff0000), 16)))
	output:write(string.char(
		bit.rshift(bit.band(src, 0xff00), 8)))
	output:write(string.char(
		bit.band(src, 0xff)))
end

local function write_uint16_be(output, src)
	output:write(string.char(
		bit.rshift(bit.band(src, 0xff00), 8)))
	output:write(string.char(
		bit.band(src, 0xff)))
end


-- https://wiki.wireshark.org/Development/LibpcapFileFormat
local function write_pcap_header(output)
	output:write("\xD4\xC3\xB2\xA1")  -- PCAP magic
	output:write("\x02\x00")  -- major version number
	output:write("\x04\x00")  -- minor version number
	output:write("\x00\x00\x00\x00")  -- thizone: gmt to local correction
	output:write("\x00\x00\x00\x00")  -- sigfigs: accuracy of timestamps, in practice always 0
	output:write("\xD0\x01\x01\x00")  -- snaplen: max length of captured packets, in octets
	output:write("\x65\x00\x00\x00")  -- linktype: data link type RAW_IP
end

local frame_start =
	-- PCAP packet header
	"\x54\x00\x00\x00" ..  -- snap length
	"\x54\x00\x00\x00" ..  -- original length
	-- IP layer
	"\x60\x00\x00\x00" ..  -- IP version 6 and no flags
	"\x00\x2c" ..  -- IP payload length
	"\x11" ..  -- protocol payload = UDP
	"\x00" ..  -- hop limit
	"\xfd\x00\x00\x00\x00\x00\x00\x00\x02\x11\x66\x8e" -- source address WITHOUT last 4 octets

local header_end =
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01" .. -- full dest address
	-- UDP
	"\x00\x35" ..  -- source port
	"\x00\x35" ..  -- dest port
	"\x00\x2c" ..  -- UDP length incl. UDP header (= payload + 8 bytes)
	"\x00\x00"     -- checksum (disabled/ignored)

-- DNS payload WITHOUT message ID, query . NS +RD
--local dns_payload = "\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01"

-- server.example.net
local dns_payload = "\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00\x06\x73\x65\x72\x76\x65\x72\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x6e\x65\x74\x00\x00\x01\x00\x01"

local function write_frame(output, source_id)
	output:write(frame_start)
	write_uint32_be(output, source_id)
	output:write(header_end)
	write_uint16_be(output, math.random(0, 65535))
	output:write(dns_payload)
end

local cache_sec
local cache_sec_bytes
local function write_timestamps(output, now_sec)
	local sec_int = math.floor(now_sec)
	local usec_int = math.floor((now_sec - sec_int) * 1e6)
	-- unix timestamp in seconds
	if cache_sec == sec_int then
		output:write(cache_sec_bytes)
	else
		cache_sec_bytes = write_uint32_le(output, sec_int)
		cache_sec = sec_int
	end
	-- microseconds since second
	write_uint32_le(output, usec_int)
end

local log = require("dnsjit.core.log").new("generate-const-qps.lua")
local getopt = require("dnsjit.lib.getopt").new({
	{ "c", "clients", 1, "number of source IP addresses to generate", "?" },
	{ "q", "qps", 1, "queries per second to generate", "" },
	{ "t", "time-limit", math.huge, "length of query stream in seconds", "?" },
	{ "u", "uniform-clients", false, "do not randomize source IP addresses, do round robin", "?" },
	{ "w", "write", "-", "output file to write, - means stdout (default)", "?" },
})
local ok, left = pcall(getopt.parse, getopt)
if not ok or #left > 0 or getopt:val("help")
	or getopt:val("clients") < 1 or getopt:val("clients") > 2^32
	or getopt:val("time-limit") <= 0 or getopt:val("qps") < 1 then
	log:info("Generate DNS query stream with uniform QPS and given number of source IP addresses.")
	getopt:usage()
	if not ok then
		log:fatal(left)
	elseif #left > 0 then
		log:fatal('unsupported extra arguments on command line')
	end
	return
end

local output
if getopt:val("write") == "-" then
	output = io.stdout
else
	output = io.open(getopt:val("write"), "w")
end
if output == nil then
	log:fatal("cannot open output file %s", getopt:val("write"))
	return
end

local clients = getopt:val("clients")
local uniform_clients = clients == 1 or getopt:val("uniform-clients")
local packet_interval = 1/getopt:val("qps")
local end_sec = getopt:val("time-limit")

write_pcap_header(output)

local now_sec = 0
local i_client = 0
while (now_sec <= end_sec)
do
	write_timestamps(output, now_sec)
	write_frame(output, i_client)
	now_sec = now_sec + packet_interval
	if uniform_clients then
		i_client = (i_client + 1) % clients
	else
		i_client = math.random(0, clients - 1)
	end
end
