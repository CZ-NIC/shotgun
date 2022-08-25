#!/usr/bin/env dnsjit
-- TODO SPDX
-- TODO rename
--
-- generate-pcap.lua: create PCAP for handshake testing
--
-- The script can generate the following PCAP:
-- - every client sends only a single query
-- - query is always the same - shotgun.test A
-- - clients are equidistantly spread out in time
--
-- Purpose of the generated PCAP is testing establishment of connections -
-- basically storming the server with handshakes.


--- Check if a file or directory exists in this path
local function exists(file)
   local ok, err, code = os.rename(file, file)
   if not ok then
      if code == 13 then
         -- Permission denied, but it exists
         return true
      end
   end
   return ok, err
end

local seed_def = os.time() + os.clock() / 1e6
local dir = os.getenv("PWD") or ""
local bit = require("bit")
local ffi = require("ffi")
local output = require("dnsjit.output.pcap").new()
local layer = require("dnsjit.filter.layer").new()
local object = require("dnsjit.core.objects")
local log = require("dnsjit.core.log").new("generate-pcap.lua")
local getopt = require("dnsjit.lib.getopt").new({
	{ "O", "outdir", dir, "directory for client chunks (must exist)", "?" },
	{ "d", "duration", 60, "duration of each chunk (in seconds)", "?" },
	{ "D", "delay", 1000, "delay between individual clients (in usecs)", "?" },
	{ nil, "seed", seed_def, "seed for RNG", "?" },
})

local SNAPLEN = 66000
local LINKTYPE = 12  -- DLT_RAW in Linux, see https://github.com/the-tcpdump-group/libpcap/blob/master/pcap/dlt.h
local HEADERSLEN = 40 + 8  -- IPv6 header and UDP header

log:enable("all")

-- Parse arguments
local args = {}
getopt:parse()
args.duration = getopt:val("d")
args.outdir = getopt:val("O")
args.delay = getopt:val("D")
args.num_chunks = getopt:val("n")
args.seed = getopt:val("seed")
math.randomseed(args.seed)

-- Display help
if getopt:val("help") then
	getopt:usage()
	return
end

-- Check arguments
if args.duration <= 0 then
	log:fatal("duration must be positive")
else
	log:notice("duration of chunk(s): " .. args.duration)
end
if args.outdir == "" or not exists(args.outdir .. "/") then
	log.fatal("output directory \"" .. args.outdir .. "\" doesn't exist")
end


local i_chunk = 0
local chunk_id
local write, writectx
local outfilename
local function open_pcap()
	if args.stdout then
		outfilename = "-"
	else
		outfilename = args.outdir .. "/" .. chunk_id .. ".pcap"
		if exists(outfilename) then
			log:warning("chunk_id collision detected! skipping: " .. outfilename)
			return false
		end
	end
	if output:open(outfilename, LINKTYPE, SNAPLEN) ~= 0 then
		log:fatal("failed to open chunk file " .. outfilename)
	else
		log:notice("writing chunk: " .. outfilename)
	end
	write, writectx = output:receive()
	return true
end


-- shotgun.test A as sent by dig
PAYLOAD = { 0x73, 0xa2, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
0x01, 0x07, 0x73, 0x68, 0x6f, 0x74, 0x67, 0x75, 0x6e, 0x04, 0x74, 0x65, 0x73,
0x74, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00,
0x00, 0x00, 0x00, 0x0c, 0x00, 0x0a, 0x00, 0x08, 0xf2, 0x4c, 0xa5, 0x7a, 0xb7,
0xb3, 0x0d, 0x10}

local pl_bytes = ffi.new("uint8_t[?]", #PAYLOAD)
for i=1,#PAYLOAD,1
do
	pl_bytes[i-1] = PAYLOAD[i]
end

local obj_pcap_out = ffi.new("core_object_pcap_t")
obj_pcap_out.obj_type = object.PCAP

local bytes = ffi.new("uint8_t[?]", SNAPLEN)
bytes[0] = 0x60  -- IPv6 header
-- UDP len in bytes[4]:bytes[5]
bytes[6] = 0x11  -- next header: UDP
bytes[8] = 0xfd  -- bytes[8]:bytes[23] source IPv6 fd00::
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
local i_client = 0
local ct_4b = ffi.typeof("uint8_t[4]")
local now_usec = 0


local function check_output()
	if output:have_errors() then
		log:fatal("error writting to file %s", outfilename)
	end
end

local function chunk_init()
	local opened
	repeat
		-- assign random "unique" chunk ID
		bytes[16] = math.random(0, 255)
		bytes[17] = math.random(0, 255)
		bytes[18] = math.random(0, 255)
		bytes[19] = math.random(0, 255)
		chunk_id = string.format("%02x%02x%02x%02x", bytes[16], bytes[17], bytes[18], bytes[19])
		opened = open_pcap()
	until(opened)

	clients = {}
	i_client = 0
	i_chunk = i_chunk + 1
	now_usec = 0
end

local function chunk_finalize()
	check_output()
	output:close()
	log:info(string.format("    number of clients: %d", i_client))
	if i_client == 0 then
		log:warning("    deleting empty chunk, double check your data")
		os.remove(outfilename)
	end
end

local src_ip
local npacketsout = 0
for packet_usec = 0,args.duration * 1e6,args.delay
do
	if packet_usec == 0 then
		chunk_init()
	end

	src_ip = ct_4b()
	put_uint32_be(src_ip, 0, i_client)

	i_client = i_client + 1

	ffi.copy(bytes + 20, src_ip, 4)

	obj_pcap_out.ts.sec = math.floor(packet_usec / 1e6)
	obj_pcap_out.ts.nsec = math.floor((packet_usec % 1e6) * 1e3)

	obj_pcap_out.len = HEADERSLEN + #PAYLOAD
	obj_pcap_out.caplen = obj_pcap_out.len

	put_uint16_be(bytes, 4, 0x003d)  -- IPv6 payload length
	put_uint16_be(bytes, 40, 0x0035)  -- normalized src port 53
	put_uint16_be(bytes, 42, 0x0035)  -- normalized dst port 53
	put_uint16_be(bytes, 44, 0x003d)  -- UDP length
	put_uint16_be(bytes, 46, 0x748a)  -- UDP checksum
	ffi.copy(bytes + HEADERSLEN, pl_bytes, #PAYLOAD)

	-- check output state only every 10 000 packets - optimization
	if npacketsout % 10000 == 0 then
		check_output()
	end
	write(writectx, obj_pcap_out:uncast())
end

chunk_finalize()
