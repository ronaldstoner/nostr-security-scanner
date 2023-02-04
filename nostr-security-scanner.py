#!/usr/bin/env python3
#
# Project:      nostr deleted events parser
# Members:      ronaldstoner
#
# Changelog
# 0.1 - Initial PoC
version = "0.1"

import asyncio
import coloredlogs
import datetime
import logging
import json
import re
import time
import websockets
from itertools import islice
from collections import defaultdict
from pymongo import MongoClient

relay_timeout = 5                   # Timeout to close relay websocket
ping_keepalive = 30                 # Ping keep alive time
#min_score = 250                    # Arbitrary minimum overall spam score to filter final results
log_level = "INFO"                 # INFO, DEBUG, WARNING, ERROR, CRITICAL
search_days = 1                   # How many days of events to query from relay
mongo_server = "localhost:27017"    # Mongodb server to store data

# Different relays may give different results. Some timeout, some loop, some keep alive.
relay = "wss://relay.stoner.com"

# Create a logger object.
logger = logging.getLogger(__name__)

# Set up logger and log l1evel
coloredlogs.install(level=log_level)
#coloredlogs.install(level=log_level, logger=logger)  # Program only - no libraries

# Connect to MongoDB
client = MongoClient("mongodb://" + mongo_server)
try:
    db = client["relay"]
except:
    logger.critical(f"Could not connect to mongodb at {mongo_server}. Exiting.")
logger.info(f"Connected to monogodb at {mongo_server}")

# Define database tables
events_collection = db["events"]        # Raw event data
pubkeys_collection = db["pubkeys"]      # pubkey, score

# Load detection rules
logger.info("Loading event security detection ruleset")
try:
    with open('rules.json', 'r') as f:
        ruleset = json.load(f)
        # Filter the rules to only include ones that start with "0"
        ruleset = {key: value for key, value in ruleset.items() if key.startswith("0")}
except:
    logger.critical("Could not load ruleset. Exiting.")
logger.info(f"Loaded {len(ruleset)} rules from ruleset")

# Connect to remote relay via websocket and query for events
async def connect_to_relay():
    logger.info(f"Connecting to relay at {relay}...")
    async with websockets.connect(relay, ping_interval=ping_keepalive) as relay_conn:
        logger.info(f"Connected to {relay}")

        # Send a REQ message to subscribe to note events only (for now) from past X days
        logger.info("Subscribing to event types = 1")
        search_filter = {
            "kinds": [1],
            "from": (datetime.datetime.now() - datetime.timedelta(days=search_days)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        }
        await relay_conn.send(json.dumps(["REQ", "nostr-security-scanner", search_filter]))

        logger.info(f"Gathering data from {relay}...")
        while True:
            try:
                event = await asyncio.wait_for(relay_conn.recv(), timeout=relay_timeout)
                event = json.loads(event)
                #print(event[0])
                if event[0] == "EVENT":
                    logger.debug(f"EVENT: {event}")
                    await write_event(event)
            except asyncio.TimeoutError:
                logger.error("Timeout occurred, closing websocket.")
                await relay_conn.close()
                break
            except Exception as e:
                logger.error(f"Error occurred: {e}")
                await relay_conn.close()
                break
        await relay_conn.close()
        logger.info(f"Closed connection to {relay}")

# Write events to a database for future consumption
async def write_event(event):
    # Check if the event content has only 1 emoji (reactions)
    if all(ord(c) > 127 for c in event[2]['content']) and len(event[2]['content']) == 1:
        # Drop the event
        return
    else:
        # Check if an event with the same id already exists in the database
        event_id = event[2]["id"]
        existing_event = events_collection.find_one({"event.id": event_id})
        if existing_event:
            logger.debug(f"Event with id {event_id} already exists in the database")
            return
        else:
            # Convert event list into a dictionary and store in database
            event_dict = {"event": event[2]}
            try:
                events_collection.insert_one(event_dict)
                logger.info("Event written to mongodb")
            except Exception as e:
                logger.info(f"Could not write event to mongodb - {e}")
                return

# Main program loop
if __name__ == "__main__":
    try:
        asyncio.run(connect_to_relay())
        logger.info("The program has finished.")
    except Exception as e:
        logger.critical(f"Exception: {e}")
