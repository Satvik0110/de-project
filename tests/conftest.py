"""Shared pytest setup.

Windows: async psycopg (dashboard API, summariser) cannot run on the default
ProactorEventLoop. Use the selector loop, as `uvicorn ... --loop asyncio:SelectorEventLoop`
does when the dashboard is run on Windows. No effect on Linux.
"""
import asyncio
import sys

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
