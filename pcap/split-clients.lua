#!/usr/bin/env dnsjit

-- split-clients.lua: randomize which clients (IPs) will be included in which
-- output file
--
-- Every unique IP (client) will be assigned to a one output file.
-- All of client's packets remain intact and go into a single file.

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

local ffi = require("ffi")
local input = require("dnsjit.input.pcap").new()
local layer = require("dnsjit.filter.layer").new()
local object = require("dnsjit.core.objects")
local log = require("dnsjit.core.log").new("split-clients.lua")
local getopt = require("dnsjit.lib.getopt").new({
	{ "r", "read", "", "input file to read", "?" },
	{ "O", "outdir", "", "directory for client chunks (must exist)", "?" },
	{ "n", "noutputs", 0, "number of output files", "?" },
	{ nil, "seed", 0, "seed for RNG", "?" },
})

local SNAPLEN = 66000
local LINKTYPE = 12  -- DLT_RAW in Linux, see https://github.com/the-tcpdump-group/libpcap/blob/master/pcap/dlt.h

log:enable("all")

-- Parse arguments
local args = {}
getopt:parse()
args.read = getopt:val("r")
args.outdir = getopt:val("O")
args.noutputs = getopt:val("n")
args.seed = getopt:val("seed")
math.randomseed(args.seed)

-- Display help
if getopt:val("help") then
	getopt:usage()
	return
end

-- Prepare output directories
if args.outdir == "" then
	getopt:usage()
	log:fatal("output directory must be specified, use -O")
elseif not exists(args.outdir .. "/") then
	log.fatal("output directory \"" .. args.outdir .. "\" doesn't exist")
end

-- Check arguments
if args.noutputs <= 1 then
	log:fatal("number of output files must be greater than 1")
end

-- Set up input
if args.read ~= "" then
	if input:open_offline(args.read) ~= 0 then
		log:fatal("failed to open input PCAP " .. args.read)
	end
	log:notice("using input PCAP " .. args.read)
else
	getopt:usage()
	log:fatal("input must be specified, use -r")
end

layer:producer(input)
local produce, pctx = layer:produce()

local outputs = {}
for n = 1, args.noutputs do
	local output = require("dnsjit.output.pcap").new()
	local out_fn = string.format("%s/%d.pcap", args.outdir, n)
	if output:open(out_fn, LINKTYPE, SNAPLEN) ~= 0 then
		log:fatal("failed to open chunk file " .. out_fn)
	else
		log:notice("created output PCAP: " .. out_fn)
	end

	outputs[n] = { fn = out_fn, output = output, nclients = 0, npackets = 0 }
	outputs[n]['write'], outputs[n]['writectx'] = output:receive()
end

local nclients = 0
local client2output = {}

local npackets = 0
local ip_len = 16
local obj, obj_ip, output_id, src_ip, write, writectx
while true do
	obj = produce(pctx)
	if obj == nil then break end
	npackets = npackets + 1

	obj_ip = obj:cast_to(object.IP6)
	assert(obj_ip ~= nil, 'no IPv6 header found, use output from '
			      .. 'extract-clients.lua as input for this script')

	src_ip = ffi.string(obj_ip.src, ip_len)
	output_id = client2output[src_ip]
	if output_id == nil then
		output_id = math.random(1, args.noutputs)
		client2output[src_ip] = output_id
		outputs[output_id]['nclients'] = outputs[output_id]['nclients'] + 1
		nclients = nclients + 1
	end

	write, writectx = outputs[output_id]['write'], outputs[output_id]['writectx']
	outputs[output_id]['npackets'] = outputs[output_id]['npackets'] + 1
	write(writectx, obj)
end

if npackets == 0 then
	log:fatal("no input packets processed!")
else
	log:info("processed %0.f input packets", npackets)
end
for _, output in pairs(outputs) do
	log:info("%s: clients: %0.f packets: %0.f", output['fn'], output['nclients'], output['npackets'])
end

-- stats for sanity checks: min, max, and (deviation / average * 100) for clients and packets
local stats = {}
local avgs = {nclients = nclients / args.noutputs, npackets = npackets / args.noutputs}
for _, stat_name in pairs({'nclients', 'npackets'}) do
	stats[stat_name] = {abs = {min=tonumber('inf'), max=tonumber('-inf')}, err = {}}
	local abs = stats[stat_name].abs  -- absolute values
	local err = stats[stat_name].err  -- deviation from per-output average as float
	for func, _ in pairs(abs) do
		for _, output in pairs(outputs) do
			abs[func] = math[func](abs[func], output[stat_name])
		end
	end
	local avg = avgs[stat_name]
	-- procentual deviations from average (expected value)
	for func, _ in pairs(abs) do
		err[func] = (abs[func] - avg) / avg
	end
end
for stat_name, _ in pairs(stats) do
	log:notice("deviation from average number of %s in range <%0.1f, %0.1f> %% per "
		   .. "output file (average %0.f)", stat_name,
		   stats[stat_name].err.min * 100,
		   stats[stat_name].err.max * 100,
		   avgs[stat_name])
end
