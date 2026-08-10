#!/usr/bin/env dnsjit
-- Convert a raw DNS-TCP-framed stream (2-byte BE length prefix + DNS wire
-- message, repeated) on stdin into a PCAP file containing IPv6/UDP/DNS
-- packets on stdout.
--
-- Writes a classic (non-nanosecond) PCAP file directly (LINKTYPE_RAW=101,
-- raw IP packets, no link-layer header) using plain Lua string building,
-- since dnsjit's output.pcap module has no public constructor for
-- synthetic core_object_pcap_t objects.
--
-- Always uses ::1 on both ends, port 53 on both ends.
--
-- usage: dnsjit tcpdns2pcap.lua [spacing_us] < in.tcpdns > out.pcap

local bit = require("bit")

local spacing_us = tonumber(arg[2]) or 300000

local src_port = 53
local dst_port = 53

local IP6_LOOPBACK = string.rep("\0", 15) .. "\1" -- ::1

local function u16_be(v)
	return string.char(
		bit.band(bit.rshift(v, 8), 0xff),
		bit.band(v, 0xff))
end

local function u32_be(v)
	return string.char(
		bit.band(bit.rshift(v, 24), 0xff),
		bit.band(bit.rshift(v, 16), 0xff),
		bit.band(bit.rshift(v, 8), 0xff),
		bit.band(v, 0xff))
end

local function read_u16_be(str, pos)
	return bit.bor(bit.lshift(str:byte(pos), 8), str:byte(pos + 1))
end

local function build_packet(dns_wire)
	local udp_len = 8 + #dns_wire

	-- UDP checksum is left as 0 (disabled/ignored): dnsjit's packet-layer
	-- parser never validates it, it only reads ports/length to locate the
	-- DNS payload. See pcap/generate-const-qps.lua, which does the same.
	local udp_hdr = u16_be(src_port) .. u16_be(dst_port) .. u16_be(udp_len) .. u16_be(0)

	local ip6_hdr = string.char(0x60, 0x00, 0x00, 0x00) -- version=6, traffic class/flow label=0
		.. u16_be(udp_len) -- payload length
		.. string.char(17) -- next header = UDP
		.. string.char(64) -- hop limit
		.. IP6_LOOPBACK -- source address
		.. IP6_LOOPBACK -- dest address

	return ip6_hdr .. udp_hdr .. dns_wire
end

-- LINKTYPE_RAW per the tcpdump.org linktype registry (portable across
-- platforms) rather than the OS-local DLT_RAW (12 on Linux, 14 on OpenBSD).
-- See pcap/generate-const-qps.lua, which uses the same value.
local LINKTYPE_RAW = 101

-- Written fully big-endian, including the magic number itself. Readers
-- (libpcap, dnsjit's fpcap/mmpcap) detect the byte-swapped magic
-- (0xa1b2c3d4 on disk reads back as 0xd4c3b2a1 on our little-endian host)
-- and transparently byte-swap every other field on read -- this is the
-- standard "swapped-endian" pcap dialect, not a dnsjit extension.
local hdr = u32_be(0xa1b2c3d4) -- magic
	.. u16_be(2) -- version_major
	.. u16_be(4) -- version_minor
	.. u32_be(0) -- thiszone
	.. u32_be(0) -- sigfigs
	.. u32_be(65535) -- snaplen
	.. u32_be(LINKTYPE_RAW) -- network
io.stdout:write(hdr)

-- stream tcpdns messages one at a time: read length prefix, read that many
-- bytes, build+write the packet immediately -- no buffering of the whole
-- input stream or the parsed message list in memory.
local ts_sec = 0
local ts_usec = 0
local count = 0
while true do
	local len_bytes = io.stdin:read(2)
	if not len_bytes or #len_bytes == 0 then
		break
	end
	assert(#len_bytes == 2, "truncated tcpdns stream: incomplete length prefix")
	local len = read_u16_be(len_bytes, 1)
	local msg = io.stdin:read(len)
	assert(msg and #msg == len, "truncated tcpdns stream")

	local packet = build_packet(msg)
	local rec = u32_be(ts_sec) .. u32_be(ts_usec) .. u32_be(#packet) .. u32_be(#packet)
	io.stdout:write(rec)
	io.stdout:write(packet)

	ts_usec = ts_usec + spacing_us
	while ts_usec >= 1000000 do
		ts_usec = ts_usec - 1000000
		ts_sec = ts_sec + 1
	end
	count = count + 1
end

io.stderr:write(string.format("wrote %d packets to stdout\n", count))
