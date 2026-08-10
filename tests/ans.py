#!/usr/bin/env python3
"""Run a bare AsyncDnsServer instance for manual/ad-hoc testing.

usage: ans.py [port]
"""
from asyncserver import AsyncDnsServer

if __name__ == "__main__":
    AsyncDnsServer().run()
