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
local input = require("dnsjit.input.pcap").new()
local output = require("dnsjit.output.pcap").new()
local layer = require("dnsjit.filter.layer").new()
local object = require("dnsjit.core.objects")
local log = require("dnsjit.core.log").new("extract-clients.lua")
local getopt = require("dnsjit.lib.getopt").new({
	{ "r", "read", "", "input file to read", "?" },
	{ "O", "outdir", dir, "directory for client chunks (must exist)", "?" },
	{ "d", "duration", 0, "duration of each chunk (in seconds, 0 means entire file)", "?" },
	{ "k", "keep", false, "keep last chunk even if it's incomplete", "?" },
	{ nil, "seed", seed_def, "seed for RNG", "?" },
	{ nil, "stdout", false, "output to stdout as a single file, no splits", "?" },
})

local SNAPLEN = 66000
local LINKTYPE = 12  -- DLT_RAW in Linux, see https://github.com/the-tcpdump-group/libpcap/blob/master/pcap/dlt.h
local HEADERSLEN = 40 + 8  -- IPv6 header and UDP header

log:enable("all")

-- Parse arguments
local args = {}
getopt:parse()
args.read = getopt:val("r")
args.duration = getopt:val("d")
args.keep = getopt:val("k")
args.outdir = getopt:val("O")
args.seed = getopt:val("seed")
args.stdout = getopt:val("stdout")
math.randomseed(args.seed)

-- Display help
if getopt:val("help") then
	getopt:usage()
	return
end

-- Check arguments
if args.stdout then
	if args.duration ~= 0 or args.outdir ~= "" then
		log.fatal("--stdout is mutualy exclusive with -d and -O, use -O ''")
	end
end
if args.duration < 0 then
	log:fatal("duration can't be negative")
elseif args.duration == 0 then
	args.duration = math.huge
	log:notice("processing entire file as one chunk")
else
	log:notice("file will be split every " .. args.duration .. " seconds")
end
if not args.stdout and (args.outdir == "" or not exists(args.outdir .. "/")) then
	log.fatal("output directory \"" .. args.outdir .. "\" doesn't exist")
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
local now_ms, diff_ms, chunk_since_ms, chunk_until_ms

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

	chunk_since_ms = chunk_until_ms or now_ms
	chunk_until_ms = chunk_since_ms + args.duration * 1e3
end

local function chunk_finalize()
	check_output()
	output:close()
	local duration_s = (chunk_until_ms - chunk_since_ms) / 1e3
	log:info(string.format("    duration_s: %.3f", duration_s))
	log:info(string.format("    number of clients: %d", i_client))
	if i_client == 0 then
		log:warning("    deleting empty chunk, double check your data")
		os.remove(outfilename)
	end
end

local obj, obj_pcap_in, obj_ip, obj_udp, obj_pl, client, src_ip, ip_len, prev_ms
local npacketsout = 0
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
		if prev_ms then
			if (now_ms < prev_ms) then
				log:fatal('non-monotonic packet timestamp detected, exiting '
					.. '(current ts %f < previous %f)', now_ms, prev_ms)
				break
			end
		end
		prev_ms = now_ms
		while chunk_until_ms == nil or now_ms >= chunk_until_ms do
			if chunk_until_ms ~= nil then
				chunk_finalize()
			end
			chunk_init()
		end

		src_ip = ffi.string(obj_ip.src, ip_len)
		client = clients[src_ip]
		if client == nil then
			client = { addr = ct_4b(), queries = 0 }
			put_uint32_be(client["addr"], 0, i_client)
			i_client = i_client + 1
			clients[src_ip] = client
		end
		client["queries"] = client["queries"] + 1
		ffi.copy(bytes + 20, client["addr"], 4)

		diff_ms = now_ms - chunk_since_ms
		obj_pcap_out.ts.sec = math.floor(diff_ms / 1e3)
		obj_pcap_out.ts.nsec = math.floor((diff_ms % 1e3) * 1e6)

		obj_pcap_out.len = HEADERSLEN + obj_pl.len
		obj_pcap_out.caplen = obj_pcap_out.len

		put_uint16_be(bytes, 4, obj_udp.ulen)  -- IPv6 payload length
		put_uint16_be(bytes, 40, 0x0035)  -- normalized src port 53
		put_uint16_be(bytes, 42, 0x0035)  -- normalized dst port 53
		put_uint16_be(bytes, 44, obj_udp.ulen)
		put_uint16_be(bytes, 46, obj_udp.sum)
		ffi.copy(bytes + HEADERSLEN, obj_pl.payload, obj_pl.len)

		-- check output state only every 10 000 packets - optimization
		if npacketsout % 10000 == 0 then
			check_output()
		end
		write(writectx, obj_pcap_out:uncast())
		npacketsout = npacketsout + 1
	end
end

if now_ms == nil then
	log:fatal("no valid packets found")
end

chunk_finalize()

if args.duration ~= math.huge and not args.keep then
	log:notice("removing incomplete last chunk "..outfilename)
	os.remove(outfilename)
end
