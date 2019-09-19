#!/usr/bin/env dnsjit
local object = require("dnsjit.core.objects")
local log = require("dnsjit.core.log")
local getopt = require("dnsjit.lib.getopt").new({
	{ "v", "verbose", 0, "Enable and increase verbosity for each time given", "?+" },
	{ "t", "threads", 1, "Number of sender threads", "?" },
	{ "p", "port", 53, "Target port", "?" },
	{ "s", "server", "::1", "Target IPv6 address", "?" },
	{ "b", "bind", "", "Source IPv6 bind address (pattern)", "?" },
	{ "d", "drift", 1.0, "Maximum realtime drift", "?" },
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

local SEND_THREADS = getopt:val("t")
local TARGET_IP = getopt:val("s")
local TARGET_PORT = getopt:val("p")
local BIND_IP_PATTERN = getopt:val("b")
local REALTIME_DRIFT = getopt:val("d")
local CHANNEL_SIZE = 16384
local MAX_CLIENTS_DNSSIM = 100000
local MAX_BATCH_SIZE = 512


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
			--recv(rctx, obj)
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

local function thread_filter(thr)
	local split = require("dnsjit.filter.dnssim").new()
	local log = require("dnsjit.core.log")

	local chann_in = thr:pop()

	local n_out = thr:pop()
	local channels = {}
	for ic=1,n_out do
		channels[ic] = thr:pop()
		split:receiver(channels[ic])
	end

	local recv, rctx = split:receive()
	while true do
		local obj = chann_in:get()

		-- read available data from channel
		while obj ~= nil do
			recv(rctx, obj)
			obj = chann_in:get()
		end

		-- check if channel is still open
		if chann_in.closed == 1 then
			for ic=1,n_out do
				channels[ic]:close()
			end
			break
		end
	end
end


-- setup input
local input = require("dnsjit.input.mmpcap").new()
local delay = require("dnsjit.filter.timing").new()
local layer = require("dnsjit.filter.layer").new()
local split = require("dnsjit.filter.dnssim").new()
local copy = require("dnsjit.filter.copy").new()
input:open(pcap)
delay:realtime(REALTIME_DRIFT)
delay:producer(input)
layer:producer(delay)

-- setup threads
local thread = require("dnsjit.core.thread")
local channel = require("dnsjit.core.channel")
local outputs = {}
local threads = {}
local channels = {}

-- filter thread
local thr_filter = thread.new()
local chann_filter = channel.new(CHANNEL_SIZE)
thr_filter:start(thread_filter)
thr_filter:push(chann_filter)
thr_filter:push(SEND_THREADS)

-- send threads
for i=1,SEND_THREADS do
	channels[i] = channel.new(CHANNEL_SIZE)
	--split:receiver(channels[i])
	thr_filter:push(channels[i])

	threads[i] = thread.new()
	threads[i]:start(thread_output)
	threads[i]:push(channels[i])
	threads[i]:push(MAX_CLIENTS_DNSSIM)
	threads[i]:push(TARGET_IP)
	threads[i]:push(TARGET_PORT)
	threads[i]:push("data_"..os.time().."_"..i..".json")
	threads[i]:push(MAX_BATCH_SIZE)
	if BIND_IP_PATTERN ~= "" then
		threads[i]:push(1)
		threads[i]:push(string.format(BIND_IP_PATTERN, i))
	else
		threads[i]:push(0)
	end
end

copy:layer(object.PAYLOAD)
copy:layer(object.IP6)
--copy:receiver(split)
copy:receiver(chann_filter)


-- process PCAP
local prod, pctx = layer:produce()
local recv, rctx = copy:receive()
while true do
	local obj = prod(pctx)
	if obj == nil then break end
	recv(rctx, obj)
end

-- teardown
--for i=1,SEND_THREADS do
--	channels[i]:close()
--end
chann_filter:close()
for i=1,SEND_THREADS do
	threads[i]:stop()
end
