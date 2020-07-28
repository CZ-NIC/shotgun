#!/usr/bin/env dnsjit

-- extract-clients.lua: prepare PCAPs with client streams
--
-- Process input PCAP and assign each client a unique IPv6 address.
-- Optionally, the input PCAP can be split in into multiple chunks on desired
-- duration. Output PCAP contains just RAWIP layer with IPv6 packets.
--
-- For example, 600s of input with 10k unique clients could be split up into
-- chunks of 60s. The output files combined have more than 10k clients,
-- since a client is considered "unique" for every time chunk it appears in.
-- Depending on the traffic, the output would have anywhere between 10k and
-- 100k clients (combined).
--
-- Other tools can then be used to merge these files to "scale up" the number
-- of clients in a single time chunk.

local bit = require("bit")
local ffi = require("ffi")
local input = require("dnsjit.input.pcap").new()
local output = require("dnsjit.output.pcap").new()
local layer = require("dnsjit.filter.layer").new()
local object = require("dnsjit.core.objects")
local log = require("dnsjit.core.log").new("pellet.lua")
local getopt = require("dnsjit.lib.getopt").new({
	{ "r", "read", "", "input file to read", "?" },
	{ "w", "write", "clients%04d.pcap", "output filename template", "?" },
	{ "t", "time", 0, "time duration of each chunk (in seconds, 0 means entire file)", "?" },
	{ "k", "keep", false, "keep last chunk even if it's incomplete", "?" },
	{ "", "csv", "time_s,period_time_since_ms,period_time_until_ms,period_queries,total_queries,period_qps,total_qps",
		"format of output CSV (header)", "?" },
})

local SNAPLEN = 66000
local LINKTYPE = 12  -- DLT_RAW in Linux, see https://github.com/the-tcpdump-group/libpcap/blob/master/pcap/dlt.h
local HEADERSLEN = 40 + 8  -- IPv6 header and UDP header

math.randomseed(os.time() + os.clock() / 1e6)

log:enable("all")

-- Parse arguments
local args = {}
getopt:parse()
args.read = getopt:val("r")
args.write = getopt:val("w")
args.time = getopt:val("t")
args.keep = getopt:val("k")
args.csv = getopt:val("csv")  -- TODO add statistics

-- Check arguments
if args.time < 0 then
	log:fatal("time duration can't be negative")
elseif args.time == 0 then
	args.time = math.huge
	log:notice("processing entire file as one chunk")
else
	log:notice("file will be split every "..args.time.." seconds")
end
if args.write == "" then
	log:fatal("output filename template must be specified")
elseif string.format(args.write, 0) == string.format(args.write, 1) and args.time ~= math.huge then
	log:fatal("output filename must be a template, use %d to specify a number in filename")
end

-- Set up input
if args.read ~= "" then
	if input:open_offline(args.read) ~= 0 then
		log:fatal("failed to open input PCAP "..args.read)
	end
	log:notice("using input PCAP "..args.read)
else
	log:fatal("input must be specified, use -r")
end
layer:producer(input)
local produce, pctx = layer:produce()


local i_chunk = 0
local write, writectx
local outfilename
local function open_pcap()
	output:close()
	outfilename = string.format(args.write, i_chunk)
	if output:open(outfilename, LINKTYPE, SNAPLEN) ~= 0 then
		log:fatal("failed to open output PCAP "..outfilename)
	else
		log:notice("using output PCAP "..outfilename)
	end
	write, writectx = output:receive()
end


local obj_pcap_out = ffi.new("core_object_pcap_t")
obj_pcap_out.obj_type = object.PCAP

local bytes = ffi.new("uint8_t[?]", SNAPLEN)
bytes[0] = 0x60  -- IPv6 header
-- UDP len in bytes[4]:bytes[5]
bytes[6] = 0x11  -- next header: UDP
-- bytes[8]:bytes[23] -- source IPv6
bytes[8] = 0x20
bytes[9] = 0x01
bytes[10] = 0x0d
bytes[11] = 0xb8
bytes[12] = 0xde
bytes[13] = 0xad
bytes[14] = 0xbe
bytes[15] = 0xef
bytes[39] = 0x01  -- dst IPv6 ::1
obj_pcap_out.bytes = bytes

local function put_uint16_be(dst, offset, src)
	dst[offset] = bit.rshift(bit.band(src, 0xff00), 8)
	dst[offset + 1] = bit.band(src, 0xff)
end

local function put_uint32_be(dst, offset, src)
	dst[offset] = bit.rshift(bit.band(src, 0xff000000), 24)
	dst[offset + 1] = bit.rshift(bit.band(src, 0xff0000), 16)
	dst[offset + 2] = bit.rshift(bit.band(src, 0xff00), 8)
	dst[offset + 3] = bit.band(src, 0xff)
end

local clients = {}
local i_client = 1
local ct_4b = ffi.typeof("uint8_t[4]")

local function chunk_init()
	open_pcap()
	-- assign random "unique" chunk ID
	bytes[16] = math.random(0, 255)
	bytes[17] = math.random(0, 255)
	bytes[18] = math.random(0, 255)
	bytes[19] = math.random(0, 255)

	clients = {}
	i_client = 1
	i_chunk = i_chunk + 1
end

local now_ms, next_chunk_ms, obj, obj_pcap_in, obj_ip, obj_udp, obj_pl, client, src_ip, ip_len
while true do
	obj = produce(pctx)
	if obj == nil then break end

	ip_len = 4
	obj_ip = obj:cast_to(object.IP)
	if obj_ip == nil then
		obj_ip = obj:cast_to(object.IP6)
		ip_len = 16
	end

	obj_udp = obj:cast_to(object.UDP)
	obj_pl = obj:cast_to(object.PAYLOAD)
	obj_pcap_in = obj:cast_to(object.PCAP)
	if obj_ip ~= nil and obj_udp ~= nil and obj_pl ~= nil and obj_pcap_in ~= nil then
		now_ms = tonumber(obj_pcap_in.ts.sec) * 1e3 + tonumber(obj_pcap_in.ts.nsec) * 1e-6
		if next_chunk_ms == nil or now_ms >= next_chunk_ms then
			chunk_init()
			next_chunk_ms = now_ms + args.time * 1e3
		end

		src_ip = ffi.string(obj_ip.src, ip_len)
		client = clients[src_ip]
		if client == nil then
			client = ct_4b()
			put_uint32_be(client, 0, i_client)
			i_client = i_client + 1
			clients[src_ip] = client
		end
		ffi.copy(bytes + 20, client, 4)

		obj_pcap_out.ts = obj_pcap_in.ts
		obj_pcap_out.len = HEADERSLEN + obj_pl.len
		obj_pcap_out.caplen = obj_pcap_out.len

		put_uint16_be(bytes, 4, obj_udp.ulen)  -- IPv6 payload length
		put_uint16_be(bytes, 40, obj_udp.sport)
		put_uint16_be(bytes, 42, obj_udp.dport)
		put_uint16_be(bytes, 44, obj_udp.ulen)
		put_uint16_be(bytes, 46, obj_udp.sum)
		ffi.copy(bytes + HEADERSLEN, obj_pl.payload, obj_pl.len)

		write(writectx, obj_pcap_out:uncast())
	end
end

output:close()

if args.time ~= math.huge and not args.keep then
	log:notice("removing incomplete last chunk "..outfilename)
	os.remove(outfilename)
end
