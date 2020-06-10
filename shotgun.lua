#!/usr/bin/env dnsjit
local object = require("dnsjit.core.objects")
local log = require("dnsjit.core.log")
local getopt = require("dnsjit.lib.getopt").new({
	{ "v", "verbose", 2, "Verbosity level (0-5)", "?" },
	{ "T", "threads", 1, "Number of sender threads", "?" },
	{ "p", "port", 53, "Target port", "?" },
	{ "s", "server", "::1", "Target IPv6 address", "?" },
	{ "t", "timeout", 2, "Timeout for requests", "?" },
	{ "k", "hanshake_timeout", 5, "Timeout for session handshake", "?" },
	{ "e", "idle_timeout", 10, "Idle timeout for TCP sessions", "?" },
	{ "P", "priority", "NORMAL", "GnutTLS priority string", "?" },
	{ "b", "bind", "", "Source IPv6 bind address pattern (example: 'fd00::%x')", "?" },
	{ "i", "ips", 1, "Number of source IPs per thread (when -b is set)", "?" },
	{ "d", "drift", 1.0, "Maximum realtime drift (seconds)", "?" },
	{ "S", "stats_interval", 5, "Log statistics every N seconds", "?" },
	{ "O", "outdir", ".", "Directory for output files (must exist)", "?" },
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
	log.display_file_line(true)
end
if v > 3 then
	log.enable("info")
end
if v > 4 then
	log.enable("debug")
end

if pcap == nil then
	print("usage: "..arg[1].." <pcap>")
	return
end

local SEND_THREADS = getopt:val("T")
local TARGET_IP = getopt:val("s")
local TARGET_PORT = getopt:val("p")
local TIMEOUT = getopt:val("t")
local HANDSHAKE_TIMEOUT = getopt:val("k")
local IDLE_TIMEOUT = getopt:val("e")
local TLS_PRIORITY = getopt:val("P")
local BIND_IP_PATTERN = getopt:val("b")
local NUM_BIND_IP = getopt:val("i")
local REALTIME_DRIFT = getopt:val("d")
local LOG_INTERVAL = getopt:val("S")
local OUTDIR = getopt:val("O")
local MAX_CLIENTS_DNSSIM = 200000
local CHANNEL_SIZE = 16384  -- empirically tested value suitable for UDP dnssim
local MAX_BATCH_SIZE = 32  -- libuv default


local function thread_output(thr)
	local channel = thr:pop()
	local output = require("dnsjit.output.dnssim").new(thr:pop())
	local running

	output:target(thr:pop(), thr:pop())
	output:timeout(thr:pop())
	output:handshake_timeout(thr:pop())
	output:idle_timeout(thr:pop())
	--output:udp_only(thr:pop())
	--output:tls(thr:pop())
	output:https2({ uri_path = "/doh", method = "POST" }, thr:pop())
	output:stats_collect(thr:pop())
	output:free_after_use(true)

	local outfile = thr:pop()
	local batch_size = thr:pop()

	local nbind = thr:pop()
	for _ = 1, nbind do
		output:bind(thr:pop())
	end

	local recv, rctx = output:receive()
	while true do
		local obj
		local i = 0

		-- read available data from channel
		while i < batch_size do
			obj = channel:try_get()
			if obj == nil then break end
			recv(rctx, obj)
			i = i + 1
		end

		-- execute libuv loop
		running = output:run_nowait()

		-- check if channel is still open
		if obj == nil and channel.closed == 1 then
			output:stats_finish()
			break
		end
	end

	-- finish processing outstanding requests
	while running ~= 0 do
		running = output:run_nowait()
	end

	output:export(outfile)
end


-- setup input
local input = require("dnsjit.input.fpcap").new()
local delay = require("dnsjit.filter.timing").new()
local layer = require("dnsjit.filter.layer").new()
local ipsplit = require("dnsjit.filter.ipsplit").new()
local copy = require("dnsjit.filter.copy").new()
input:open(pcap)
delay:realtime(REALTIME_DRIFT)
delay:producer(input)
layer:producer(delay)
ipsplit:overwrite_dst()

-- setup threads
local thread = require("dnsjit.core.thread")
local channel = require("dnsjit.core.channel")
local threads = {}
local channels = {}

-- send threads
local outname = OUTDIR.."/shotgun-"..os.time().."-%02d.json"
for i = 1, SEND_THREADS do
	channels[i] = channel.new(CHANNEL_SIZE)
	ipsplit:receiver(channels[i])

	threads[i] = thread.new()
	threads[i]:start(thread_output)
	threads[i]:push(channels[i])
	threads[i]:push(MAX_CLIENTS_DNSSIM)
	threads[i]:push(TARGET_IP)
	threads[i]:push(TARGET_PORT)
	threads[i]:push(TIMEOUT)
	threads[i]:push(HANDSHAKE_TIMEOUT)
	threads[i]:push(IDLE_TIMEOUT)
	threads[i]:push(TLS_PRIORITY)
	threads[i]:push(LOG_INTERVAL)
	threads[i]:push(string.format(outname, i))
	threads[i]:push(MAX_BATCH_SIZE)
	if BIND_IP_PATTERN ~= "" then
		threads[i]:push(NUM_BIND_IP)
		for j = 1, NUM_BIND_IP do
			local addr = string.format(BIND_IP_PATTERN, NUM_BIND_IP*(i-1)+j)
			threads[i]:push(addr)
		end
	else
		threads[i]:push(0)
	end
end

copy:obj_type(object.PAYLOAD)
copy:obj_type(object.IP6)
copy:receiver(ipsplit)


-- process PCAP
local prod, pctx = layer:produce()
local recv, rctx = copy:receive()
while true do
	local obj = prod(pctx)
	if obj == nil then break end
	recv(rctx, obj)
end

-- teardown
for i = 1, SEND_THREADS do
	channels[i]:close()
end
for i = 1, SEND_THREADS do
	threads[i]:stop()
end
