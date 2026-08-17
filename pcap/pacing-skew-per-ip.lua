#!/usr/bin/env dnsjit

-- pacing-skew-per-ip.lua: how much earlier than its own timestamp each
-- client's traffic is sent by shotgun
--
-- dnsjit's filter.timing in realtime mode consults the clock once every
-- rt_batch packets (128 by default) and sleeps until that packet's
-- timestamp; the packets between two such anchors are handed over with no
-- delay at all. A packet is therefore sent as early as the anchor that
-- precedes it, and the error equals the span of pcap time the anchor's
-- batch covers. It is unbounded in general: a batch of a sparse capture can
-- span minutes.
--
-- The anchors are counted over the whole capture, since shotgun.lua puts
-- filter.timing ahead of filter.layer -- every packet in the file moves
-- them, DNS or not. This is why the skew is reported per source address but
-- cannot be computed per source address.

local input_fpcap = require("dnsjit.input.fpcap")
local input_mmpcap = require("dnsjit.input.mmpcap")
local layer = require("dnsjit.filter.layer").new()
local object = require("dnsjit.core.objects")
local log = require("dnsjit.core.log").new("pacing-skew-per-ip.lua")
local getopt = require("dnsjit.lib.getopt").new({
	{ "r", "read", "", "input file to read (default: stdin)", "?" },
	{ nil, "csv", "", "path to the output CSV file (default: stdout)", "?" },
	{ "b", "batch", 128, "dnsjit pacing batch size (filter.timing rt_batch)", "?" },
})

log:enable("all")

local args = {}
getopt:parse()
args.read = getopt:val("r")
args.csv = getopt:val("csv")
args.batch = tonumber(getopt:val("b"))

if getopt:val("help") then
	getopt:usage()
	return
end

if args.batch == nil or args.batch < 1 then
	log:fatal("batch size must be a positive number")
end

local input
if args.read ~= "" then
	input = input_mmpcap.new()
	if input:open(args.read) ~= 0 then
		log:notice("failed to open PCAP with mmap, fallback to fpcap")
		input = input_fpcap.new()
		if input:open(args.read) ~= 0 then
			log:fatal("failed to open input PCAP "..args.read)
		end
	end
	log:notice("using input PCAP "..args.read)
else
	input = input_fpcap.new()
	if input:openfp(io.stdin) ~= 0 then
		log:fatal("failed to open PCAP on stdin")
	end
	log:notice("using input PCAP on stdin")
end
layer:producer(input)
local produce, pctx = layer:produce()

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
local n_clients = 0
local n_packets = 0
local n_without_ip = 0
local first_sec, first_nsec
local anchor_ns = 0
local worst_skew_ns = 0

local function relative_ns(ts)
	return (tonumber(ts.sec) - first_sec) * 1e9 + (tonumber(ts.nsec) - first_nsec)
end

log:info("processing... (this may take up to minutes for very large files)")
local obj, obj_pcap, obj_ip, client, src_ip, now_ns, skew_ns
while true do
	obj = produce(pctx)
	if obj == nil then break end

	obj_pcap = obj:cast_to(object.PCAP)
	if obj_pcap ~= nil then
		n_packets = n_packets + 1

		if first_sec == nil then
			first_sec = tonumber(obj_pcap.ts.sec)
			first_nsec = tonumber(obj_pcap.ts.nsec)
		end
		now_ns = relative_ns(obj_pcap.ts)

		-- The first packet initializes filter.timing without sleeping and
		-- resets its counter, so the sleeping ones are 1, 1+batch, 1+2*batch...
		if (n_packets - 1) % args.batch == 0 then
			anchor_ns = now_ns
		end
		skew_ns = now_ns - anchor_ns
		if skew_ns > worst_skew_ns then
			worst_skew_ns = skew_ns
		end

		obj_ip = obj:cast_to(object.IP)
		if obj_ip == nil then
			obj_ip = obj:cast_to(object.IP6)
		end

		if obj_ip == nil then
			-- Still counted above: filter.timing sees it and it moves the
			-- anchors, it just cannot be attributed to a client.
			n_without_ip = n_without_ip + 1
		else
			src_ip = obj_ip:source()
			client = clients[src_ip]
			if client == nil then
				client = {
					packets = 0,
					since_ns = now_ns,
					until_ns = now_ns,
					max_skew_ns = 0,
					max_skew_at_ns = now_ns,
					max_skew_at_packet = n_packets,
				}
				clients[src_ip] = client
				n_clients = n_clients + 1
			end
			client["packets"] = client["packets"] + 1
			client["until_ns"] = now_ns
			if skew_ns > client["max_skew_ns"] then
				client["max_skew_ns"] = skew_ns
				client["max_skew_at_ns"] = now_ns
				client["max_skew_at_packet"] = n_packets
			end
		end
	end
end

if n_packets == 0 then
	log:fatal("no packets in input PCAP")
end

local input_packets = tonumber(input:packets())
if input_packets ~= n_packets then
	-- The anchors are placed by packet position, so a packet that never
	-- reaches this loop shifts every one of them and invalidates the output.
	log:critical(string.format(
		"read %d packets but input reports %d; skews below are unreliable",
		n_packets, input_packets))
end

log:info(string.format("packets: %d (%d without an IP address)", n_packets, n_without_ip))
log:info(string.format("clients: %d", n_clients))
log:info(string.format("pacing batch: %d packets", args.batch))
log:info(string.format("worst skew over all packets (ms): %.3f", worst_skew_ns / 1e6))

csv_output:write('"max_skew_ms","max_skew_at_ms","max_skew_at_packet","ip","packets","ip_since_ms","ip_until_ms"\n')
for ip, data in pairs(clients) do
	csv_output:write(string.format("%.6f", data["max_skew_ns"] / 1e6))
	csv_output:write(',')
	csv_output:write(string.format("%.3f", data["max_skew_at_ns"] / 1e6))
	csv_output:write(',')
	csv_output:write(string.format("%d", data["max_skew_at_packet"]))
	csv_output:write(',"')
	csv_output:write(ip)
	csv_output:write('",')
	csv_output:write(string.format("%d", data["packets"]))
	csv_output:write(',')
	csv_output:write(string.format("%.3f", data["since_ns"] / 1e6))
	csv_output:write(',')
	csv_output:write(string.format("%.3f", data["until_ns"] / 1e6))
	csv_output:write('\n')
end
csv_output:close()
