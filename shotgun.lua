#!/usr/bin/env dnsjit
local SEND_THREADS = 1
local TARGET_IP = "fbfb::cafe"
local TARGET_PORT = 5553
local BIND_IP_PATTERN = "fbfb::%x"
local CHANNEL_SIZE = 16384
local MAX_CLIENTS_DNSSIM = 100000
local MAX_BATCH_SIZE = 512


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


local function thread_output(thr)
	local channel = thr:pop()
	local output = require("dnsjit.output.dnssim").new(thr:pop())
	local log = require("dnsjit.core.log")
	local ffi = require("ffi")
	local running

	output:udp_only()
	output:target(thr:pop(), thr:pop())
	output:free_after_use(true)

	local outfile = thr:pop()
	local MAX_BATCH_SIZE = thr:pop()

	local nbind = thr:pop()
	for i=1,nbind do
		output:bind(thr:pop())
	end

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

	output:export(outfile)
end

--local function thread_filter(thr)
--	local split = require("dnsjit.filter.dnssim").new()
--	local log = require("dnsjit.core.log")
--	local chann_in = thr:pop()
--	local chann_out1 = thr:pop()
--	--local chann_out2 = thr:pop()
--	local MAX_BATCH_SIZE = chann_in.capacity
--	split:receiver(chann_out1)
--	--split:receiver(chann_out2)
--	local recv, rctx = split:receive()
--	while true do
--		local obj
--		local i = 0
--
--		--print("thr filter: "..chann_in:size())
--		--if chann_in:is_full() == 1 then
--		--	log.fatal("filter thread can't keep up")
--		--end
--
--		-- read available data from channel
--		while i < MAX_BATCH_SIZE do
--			obj = chann_in:try_get()
--			if obj == nil then break end
--			recv(rctx, obj)
--			i = i + 1
--		end
--		-- check if channel is still open
--		if obj == nil and chann_in.closed == 1 then
--			chann_out1:close()
--			--chann_out2:close()
--			break
--		end
--	end
--end


-- setup input
local input = require("dnsjit.input.mmpcap").new()
local delay = require("dnsjit.filter.timing").new()
local layer = require("dnsjit.filter.layer").new()
local split = require("dnsjit.filter.dnssim").new()
local copy = require("dnsjit.filter.copy").new()
input:open(pcap)
delay:realtime()
delay:producer(input)

-- setup threads
local thread = require("dnsjit.core.thread")
local channel = require("dnsjit.core.channel")
local outputs = {}
local threads = {}
local channels = {}

for i=1,SEND_THREADS do
	channels[i] = channel.new(CHANNEL_SIZE)
	split:receiver(channels[i])

	threads[i] = thread.new()
	threads[i]:start(thread_output)
	threads[i]:push(channels[i])
	threads[i]:push(MAX_CLIENTS_DNSSIM)
	threads[i]:push(TARGET_IP)
	threads[i]:push(TARGET_PORT)
	threads[i]:push("data_"..os.time().."_"..i..".json")
	threads[i]:push(MAX_BATCH_SIZE)
	threads[i]:push(1)
	threads[i]:push(string.format(BIND_IP_PATTERN, i))
end

copy:layer(object.PAYLOAD)
copy:layer(object.IP6)
copy:receiver(split)

layer:producer(delay)


-- process PCAP
local prod, pctx = layer:produce()
local recv, rctx = copy:receive()
while true do
	local obj = prod(pctx)
	if obj == nil then break end
	recv(rctx, obj)
end

-- teardown
for i=1,SEND_THREADS do
	channels[i]:close()
end
for i=1,SEND_THREADS do
	threads[i]:stop()
end
