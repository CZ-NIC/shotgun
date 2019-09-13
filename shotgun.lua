#!/usr/bin/env dnsjit
local CHANNEL_SIZE = 16384
local NUM_THREADS = 2


local object = require("dnsjit.core.objects")
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
local split = require("dnsjit.filter.split").new()  -- TODO ipsplit
local copy = require("dnsjit.filter.copy").new()
input:open(pcap)
delay:keep()
delay:producer(input)
layer:producer(delay)

-- setup threads
local thread = require("dnsjit.core.thread")
local channel = require("dnsjit.core.channel")
local threads = {}
local channels = {}
for i = 1,NUM_THREADS+1 do
	threads[i] = thread.new()
	channels[i] = channel.new(CHANNEL_SIZE)
	threads[i]:start(thread_main)
	threads[i]:push(channels[i])
	split:receiver(channels[i])
end

copy:layer(object.PAYLOAD)
copy:layer(object.IP6)
copy:receiver(split)

-- process PCAP
local prod, pctx = layer:produce()
local recv, rctx = copy:receive()
while true do
	local obj = prod(pctx)
	if obj == nil then break end
	recv(rctx, obj)
end

-- close channels and join threads
for i = 1,NUM_THREADS do
	channels[i]:close()
end
for i = 1,NUM_THREADS do
	threads[i]:stop()
end
