#!/usr/bin/env dnsjit

-- cut-pcap.lua: Copy input PCAP to output until specified timestamp is reached.
-- This is an efficient implementation of editcap -B for already sorted input.

-- SPDX-FileCopyrightText: Internet Systems Consortium, Inc. ("ISC")
-- SPDX-License-Identifier: BSD-2-Clause

local fpcap = require("dnsjit.input.fpcap")
local log = require("dnsjit.core.log")
local mmpcap = require("dnsjit.input.mmpcap")
local object = require("dnsjit.core.objects")
local output = require("dnsjit.output.pcap").new()

local function open_pcap(filename)
	local input
	if filename == '-' then
		input = fpcap.new()
		if input:openfp(io.stdin) ~= 0 then
			log.fatal("failed to open PCAP on stdin")
		else
			log.debug('stdin opened using fpcap')
		end
	else
		input = mmpcap.new()
		if input:open(filename) ~= 0 then
			log.notice("failed to open PCAP with mmap, fallback to fpcap")
			input = fpcap.new()
			if input:open(filename) ~= 0 then
				log.fatal("failed to open PCAP with fpcap")
			else
				log.debug('file %s opened using fpcap', filename)
			end
		else
			log.debug('file %s opened using mmpcap', filename)
		end
	end
	local producer, pctx = input:produce()
	return producer, pctx
end

local function get_next_pkt(producer, pctx)
	local obj = producer(pctx)
	if obj ~= nil then
		return obj, obj:cast_to(object.PCAP)
	end
end

log.enable("all")
if #arg ~= 4 or not tonumber(arg[4]) then
	print("usage: "..arg[1].." <pcap file in | -> <pcap file out | -> <stop after unix timestamp>")
	print("Copy packets from input PCAP to output "
		.. "until specified timestamp or input EOF is reached")
	return
end

local in_filename = arg[2]
local out_filename = arg[3]
local stop_after = tonumber(arg[4])
if stop_after ~= math.floor(stop_after) or stop_after < 0 then
	log.fatal('unsupported stop timestamp: use an integer >= 0')
end

local producer, pctx = open_pcap(in_filename)
local cur_obj, cur_pkt = get_next_pkt(producer, pctx)
if not cur_pkt then
	log.fatal('no packets in input pcap %s, terminating', in_filename)
end

log.info('opening output file %s', out_filename)
output:open(out_filename,
	cur_pkt.linktype,
	cur_pkt.snaplen)
local receiver, rctx = output:receive()

local npackets = 0
while cur_pkt do
	if cur_pkt.ts.sec > stop_after then
		log.info('timestamp %.f reached, stop', stop_after)
		break
	end
	receiver(rctx, cur_obj)
	npackets = npackets + 1
	cur_obj, cur_pkt = get_next_pkt(producer, pctx)
end

log.info('output %.f packets', npackets)
log.debug('closing output file %s', out_filename)
output:close()
log.debug('output file %s closed', out_filename)
