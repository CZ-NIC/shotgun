#!/usr/bin/env dnsjit

-- count-packets-over-time.lua: count number of packets in input PCAP in time intervals

local input = require("dnsjit.input.pcap").new()
local layer = require("dnsjit.filter.layer").new()
local object = require("dnsjit.core.objects")
local log = require("dnsjit.core.log").new("count-packets-over-time.lua")
local getopt = require("dnsjit.lib.getopt").new({
	{ "r", "read", "", "input file to read", "?" },
	{ "s", "stats_period", 100, "period for printing stats (ms)", "?" },
	{ nil, "csv", "", "path to the output CSV file (default: stdout)", "?" },
})

log:enable("all")

-- Parse arguments
local args = {}
getopt:parse()
args.read = getopt:val("r")
args.stats_period = getopt:val("s")
args.csv = getopt:val("csv")

-- Display help
if getopt:val("help") then
	getopt:usage()
	return
end

-- Check arguments
if args.stats_period <= 0 then
	log:fatal("stats_period must be grater than 0")
end

-- Set up input
if args.read ~= "" then
	if input:open_offline(args.read) ~= 0 then
		log:fatal("failed to open input PCAP "..args.read)
	end
	log:notice("using input PCAP "..args.read)
else
	getopt:usage()
	log:fatal("input must be specified, use -r/-i")
end
layer:producer(input)
local produce, pctx = layer:produce()

-- Set up CSV
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

local Stats = {}
local StatsCounters = {}

function Stats.new(stats_period_ms, output, format)
	if stats_period_ms == nil then
		stats_period_ms = 1000
	end
	if stats_period_ms <= 0 then
		log:fatal("statistics interval must be greater than 0")
	end
	if format == nil then
		format = "time_s,period_time_since_ms,period_time_until_ms,period_packets,total_packets,period_pps,total_pps"
	end

	local self = setmetatable({
		_stats_period_ms = stats_period_ms,
		_output = output,
		_format = format,
		_time_first_ms = nil,   -- time of the very first received packet
		_time_next_ms = nil,    -- time when next stats begins
		_time_last_ms = nil,    -- time of the last received packet
		_period = StatsCounters.new(),
		_total = StatsCounters.new(),
	}, {  __index = Stats })

	if self._output ~= nil then
		self._output:write(format.."\n")
	end

	return self
end

function Stats:display()
	if self._output == nil then
		return
	end

	local period = self._period:tabulate("period")
	local total = self._total:tabulate("total")
	local additional = {
		time_s = string.format("%.03f", (self._period.time_until_ms - self._time_first_ms) / 1e3),
	}

	local outstr = string.gsub(self._format, "([_%w]+)", period)
	outstr = string.gsub(outstr, "([_%w]+)", total)
	outstr = string.gsub(outstr, "([_%w]+)", additional)

	self._output:write(outstr.."\n")
end

function Stats:receive(obj)
	local obj_pcap = obj:cast_to(object.PCAP)
	local time_pcap_ms = tonumber(obj_pcap.ts.sec) * 1e3 + tonumber(obj_pcap.ts.nsec) * 1e-6

	if self._time_first_ms == nil then
		self._time_first_ms = time_pcap_ms
		self._time_next_ms = self._time_first_ms + self._stats_period_ms
		self._period:begin(self._time_first_ms, self._time_next_ms)
		self._total:begin(self._time_first_ms, self._time_next_ms)
	end

	while time_pcap_ms >= self._time_next_ms do  -- don't skip over 0-value intervals
		self._total = self._total + self._period
		self:display()

		local next_ms = self._time_next_ms + self._stats_period_ms
		self._period:begin(self._time_next_ms, next_ms)
		self._time_next_ms = next_ms
	end

	self._period.packets = self._period.packets + 1

	-- ensure monotonic update of time
	if self._time_last_ms == nil or time_pcap_ms > self._time_last_ms then
		self._time_last_ms = time_pcap_ms
	end
end

function Stats:finish()
	if self._time_last_ms == nil then
		self._log:warning("no packets received")
		return
	elseif self._time_last_ms < self._period.time_since_ms then
		-- this shouldn't happen, handling just in case
		self._log:fatal("last packet time is less than start of measurement interval")
	elseif self._time_last_ms == self._period.time_since_ms then
		-- avoid division by zero in calculations by adding an extra millisecond
		self._time_last_ms = self._time_last_ms + 1
	end
	self._period.time_until_ms = self._time_last_ms
	self._total = self._total + self._period
	self:display()
end


function StatsCounters.new()
	local self = setmetatable({
		period_s = nil,
		time_since_ms = nil,
		time_until_ms = nil,
		packets = 0,
	}, {
		__index = StatsCounters,
		__add = function(op1, op2)
			op1.time_since_ms = math.min(op1.time_since_ms, op2.time_since_ms)
			op1.time_until_ms = math.max(op1.time_until_ms, op2.time_until_ms)
			op1.packets = op1.packets + op2.packets

			return op1
		end,
	})

	return self
end

function StatsCounters:begin(time_since_ms, time_until_ms)
	self.packets = 0
	assert(time_until_ms > time_since_ms)
	self.time_since_ms = time_since_ms
	self.time_until_ms = time_until_ms
end

function StatsCounters:tabulate(prefix)
	if prefix == nil then
		prefix = ""
	elseif string.sub(prefix, -1) ~= "_" then
		prefix = prefix .. "_"
	end

	local res = {}
	local period_s = (self.time_until_ms - self.time_since_ms) / 1e3
	res[prefix.."time_since_ms"] = string.format("%d", self.time_since_ms)
	res[prefix.."time_until_ms"] = string.format("%d", self.time_until_ms)
	res[prefix.."packets"] = string.format("%d", self.packets)
	res[prefix.."pps"] = string.format("%d", self.packets / period_s)
	return res
end

function StatsCounters:count()
	self.packets = self.packets + 1
end


local stats = Stats.new(args.stats_period, csv_output)
local obj
while true do
	obj = produce(pctx)
	if obj == nil then break end
	stats:receive(obj)
end
stats:finish()

csv_output:close()
