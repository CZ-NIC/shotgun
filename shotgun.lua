#!/usr/bin/env dnsjit
local NUM_THREADS = 4


local object = require("dnsjit.core.objects")
local ffi = require("ffi")
local log = require("dnsjit.core.log")
local getopt = require("dnsjit.lib.getopt").new({
	{ "v", "verbose", 0, "Enable and increase verbosity for each time given", "?+" },
})
local pcap = unpack(getopt:parse())
if getopt:val("help") then
	getopt:usage()
	return
end
local v = getopt:val("v")
if v > 0 then
	log.enable("warning")
end
if v > 1 then
	log.enable("notice")
end
if v > 2 then
	log.enable("info")
end
if v > 3 then
	log.enable("debug")
end

if pcap == nil then
	print("usage: "..arg[1].." <pcap>")
	return
end


local function thread_main(thr)
	-- setup output
	-- TODO: make dnssim shareable, so it's possible to use thread:pop()?
	local MAX_UDP_CLIENTS_DNSSIM = 250000
	local output = require("dnsjit.output.dnssim").new(MAX_UDP_CLIENTS_DNSSIM)
	output:udp_only()
	output:target("::1", 53535)
	output:free_after_use(true)

	local MAX_BATCH_SIZE = 32
	local channel = thr:pop()
	local unique_id = tostring( {} ):sub(8)
	local running

	local recv, rctx = output:receive()
	while true do
		local obj
		local i = 0

		-- read available data from channel
		while i < MAX_BATCH_SIZE do
			obj = channel:try_get()
			if obj == nil then break end
			recv(rctx, obj)
			i = i + 1
		end

		-- execute libuv loop
		running = output:run_nowait()

		-- check if channel is still open
		if obj == nil and channel.closed == 1 then
			break
		end
	end

	-- finish processing outstanding requests
	while running ~= 0 do
		running = output:run_nowait()
	end

	-- output results to file
	output:export("data_"..unique_id..".json")
end


-- setup input
local input = require("dnsjit.input.fpcap").new()
local delay = require("dnsjit.filter.timing").new()
local layer = require("dnsjit.filter.layer").new()
input:open(pcap)
delay:keep()
delay:producer(input)
layer:producer(delay)


-- setup threads
local channel = require("dnsjit.core.channel").new(4)
local thread = require("dnsjit.core.thread").new()
thread:start(thread_main)
thread:push(channel)

-- read PCAP, parse, copy objects and pass to channel
local prod, pctx = layer:produce()
while true do
	local obj, payload, ip6
	local srcobj = prod(pctx)
	if srcobj == nil then break end

	-- find and copy payload object
	obj = srcobj:cast()
	while (obj.obj_type ~= object.PAYLOAD and obj.obj_prev ~= nil) do
		obj = obj.obj_prev:cast()
	end
	if obj.obj_type == object.PAYLOAD then
		payload = obj:copy()

		-- find and copy IP6 object
		while (obj.obj_type ~= object.IP6 and obj.obj_prev ~= nil) do
			obj = obj.obj_prev:cast()
		end
		if obj.obj_type == object.IP6 then
			ip6 = obj:copy()
			payload.obj_prev = ffi.cast("core_object_t*", ip6)

			channel:put(payload)
		end
	end
end

channel:close()
thread:stop()
