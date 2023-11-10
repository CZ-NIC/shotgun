#!/usr/bin/env dnsjit

local object = require("dnsjit.core.objects")
local log = require("dnsjit.core.log")
local dnssim = require("shotgun.output.dnssim")

local DNSSIM_REQ_VERSION = 20210714
local has_check_version, version = pcall(dnssim.check_version, DNSSIM_REQ_VERSION)
if not has_check_version or version == nil then
	log.fatal(string.format(
		"Newer dnsjit is required. Minimum version of dnssim component is v%d.",
		DNSSIM_REQ_VERSION))
end

local getopt = require("dnsjit.lib.getopt").new({})

local confpath = unpack(getopt:parse())
if confpath == nil then
	log.fatal("lua config file must be specified as first argument")
end
local ok, config = pcall(dofile, confpath)
if not ok then
	log.fatal("failed to load lua config file \""..config.."\"")
end

if config.verbosity > 0 then
	log.enable("warning")
end
if config.verbosity > 1 then
	log.enable("notice")
end
if config.verbosity > 2 then
	log.display_file_line(true)
end
if config.verbosity > 3 then
	log.enable("info")
end
if config.verbosity > 4 then
	log.enable("debug")
end

local function send_thread_main(thr)
	local channel = thr:pop()
	local running

	-- output must be global (per thread) to be accesible in loadstring()
	-- luacheck: globals output, ignore log
	output = require("shotgun.output.dnssim").new(thr:pop())
	local log = output:log(thr:pop())

	output:target(thr:pop(), thr:pop())
	output:timeout(thr:pop())
	output:handshake_timeout(thr:pop())
	output:idle_timeout(thr:pop())

	local protocol_func = thr:pop()
	local gnutls_priority = thr:pop()
	local http_method = thr:pop()
	local cmd = "output:" .. protocol_func

	if protocol_func == "udp" then
		cmd = cmd .. "()"
	elseif protocol_func == "tcp" then
		cmd = cmd .. "()"
	elseif protocol_func == "tls" then
		cmd = cmd .. "('" .. gnutls_priority .. "')"
	elseif protocol_func == "https2" then
		cmd = cmd .. "({ method = '" .. http_method .. "' }, '" .. gnutls_priority .. "')"
	elseif protocol_func == "quic" then
		cmd = cmd .. "('" .. gnutls_priority .. "')"
	else
		log:fatal("unknown protocol_func: " .. protocol_func)
	end
	assert(loadstring(cmd))()

	output:stats_collect(1)
	output:free_after_use(true)

	local outfile = thr:pop()
	local batch_size = thr:pop()

	local nbind = thr:pop()
	for _ = 1, nbind do
		output:bind(thr:pop())
	end

	local recv, rctx = output:receive()
	local i_full = 0
	while true do
		local obj
		local i = 0

		if channel:full() then
			i_full = i_full + 1
			if i_full == 1 then
				log:debug("buffer capacity reached")
			elseif i_full == 4 then
				log:info("buffer capacity reached")
			elseif i_full == 16 then
				log:warning("buffer capacity exceeded, threads may become blocked")
			elseif i_full % 64 == 0 then
				log:critical("buffer capacity exceeded, threads are blocked")
			end
		else
			if i_full >= 16 then
				log:notice("buffer capacity restored")
			end
			i_full = 0
		end

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


---- setup input
local delay = require("dnsjit.filter.timing").new()
local layer = require("dnsjit.filter.layer").new()
local ipsplit = require("dnsjit.filter.ipsplit").new()
local copy = require("dnsjit.filter.copy").new()
local input

if config.pcap == '-' then
	input = require("dnsjit.input.fpcap").new()
	if input:openfp(io.stdin) ~= 0 then
		log.fatal("failed to open PCAP on stdin")
	end
else
	input = require("dnsjit.input.mmpcap").new()
	if input:open(config.pcap) ~= 0 then
		log.notice("failed to open PCAP with mmap, fallback to fpcap")
		input = require("dnsjit.input.fpcap").new()
		if input:open(config.pcap) ~= 0 then
			log.fatal("failed to open PCAP with fpcap")
		end
	end
end
delay:realtime(config.drift_s)
delay:producer(input)
layer:producer(delay)
ipsplit:overwrite_dst()
ipsplit:random()

-- setup threads
local thread = require("dnsjit.core.thread")
local channel = require("dnsjit.core.channel")
local threads = {}
local channels = {}

---- initialize send threads
for i, thrconf in ipairs(config.threads) do
	channels[i] = channel.new(thrconf.channel_size)
	ipsplit:receiver(channels[i], thrconf.weight)

	threads[i] = thread.new()
	threads[i]:start(send_thread_main)
	threads[i]:push(channels[i])
	threads[i]:push(thrconf.max_clients)
	threads[i]:push(thrconf.name)
	threads[i]:push(thrconf.target_ip)
	threads[i]:push(thrconf.target_port)
	threads[i]:push(thrconf.timeout_s)
	threads[i]:push(thrconf.handshake_timeout_s)
	threads[i]:push(thrconf.idle_timeout_s)
	threads[i]:push(thrconf.protocol_func)
	threads[i]:push(thrconf.gnutls_priority)
	threads[i]:push(thrconf.http_method)
	threads[i]:push(thrconf.output_file)
	threads[i]:push(thrconf.batch_size)
	threads[i]:push(#thrconf.bind_ips)
	for _, bind_ip in ipairs(thrconf.bind_ips) do
		threads[i]:push(bind_ip)
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
	if config.stop_after_s then
		local obj_pcap_in = obj:cast_to(object.PCAP)
		if obj_pcap_in.ts.sec >= config.stop_after_s then
			break
		end
	end
	recv(rctx, obj)
end
log.notice('processed %.0f packets from input PCAP', input:packets())

-- teardown
for i, _ in ipairs(config.threads) do
	channels[i]:close()
end
for i, _ in ipairs(config.threads) do
	threads[i]:stop()
end
