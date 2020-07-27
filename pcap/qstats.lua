local object = require("dnsjit.core.objects")

local QStats = {}
local QStatsCounters = {}

function QStats.new(stats_period_ms, output, format)
	if stats_period_ms == nil then
		stats_period_ms = 1000
	end
	assert(stats_period_ms > 0)  -- TODO use logger?
	if format == nil then
		format = "time_s,period_queries"
	end

	local self = setmetatable({
		_stats_period_ms = stats_period_ms,
		_output = output,
		_format = format,
		_time_first_ms = nil,   -- time of the very first received packet
		_time_next_ms = nil,    -- time when next stats begins
		_period = QStatsCounters.new(),
		_total = QStatsCounters.new(),
	}, {  __index = QStats })

	if self._output ~= nil then
		self._output:write(format.."\n")
	end

	return self
end

function QStats:display()
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

function QStats:receive(obj)
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

	self._period.queries = self._period.queries + 1
end

function QStats:finish()
	self._total = self._total + self._period
	self:display()
end


function QStatsCounters.new()
	local self = setmetatable({
		period_s = nil,
		time_since_ms = nil,
		time_until_ms = nil,
		queries = 0,
	}, {
		__index = QStatsCounters,
		__add = function(op1, op2)
			op1.time_since_ms = math.min(op1.time_since_ms, op2.time_since_ms)
			op1.time_until_ms = math.max(op1.time_until_ms, op2.time_until_ms)
			op1.queries = op1.queries + op2.queries

			return op1
		end,
	})

	return self
end

function QStatsCounters:begin(time_since_ms, time_until_ms)
	self.queries = 0
	assert(time_until_ms > time_since_ms)
	self.time_since_ms = time_since_ms
	self.time_until_ms = time_until_ms
end

function QStatsCounters:tabulate(prefix)
	if prefix == nil then
		prefix = ""
	elseif string.sub(prefix, -1) ~= "_" then
		prefix = prefix .. "_"
	end

	local res = {}
	local period_s = (self.time_until_ms - self.time_since_ms) / 1e3
	res[prefix.."time_since_ms"] = string.format("%d", self.time_since_ms)
	res[prefix.."time_until_ms"] = string.format("%d", self.time_until_ms)
	res[prefix.."queries"] = string.format("%d", self.queries)
	res[prefix.."qps"] = string.format("%d", self.queries / period_s)
	return res
end

function QStatsCounters:count()
	self.queries = self.queries + 1
end


return QStats
