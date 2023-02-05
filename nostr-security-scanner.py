#!/usr/bin/env python3
#
# Project:      nostr deleted events parser
# Members:      ronaldstoner
#
version = "0.1.3"

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
relays = "wss://relay.damus.io,wss://relay.stoner.com"

# Create a logger object.
logger = logging.getLogger(__name__)

# Set up logger and log l1evel
coloredlogs.install(level=log_level)
#coloredlogs.install(level=log_level, logger=logger)  # Program only - no libraries

# Connect to MongoDB
client = MongoClient("mongodb://" + mongo_server)
try:
    db = client["nostr-security"]
except:
    logger.critical(f"Could not connect to mongodb at {mongo_server}. Exiting.")
logger.info(f"Connected to monogodb at {mongo_server}")

# Define database tables
events_collection = db["events"]        # Raw event data
pubkeys_collection = db["pubkeys"]      # pubkey, score

# Rule 002 - Define dictionary to keep track of event content count for each pubkey
duplicate_count = defaultdict(lambda: defaultdict(int))

# Rule 003 - Define dictionary to track bursting of events from a pubkey
pubkey_burst = {}

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

async def connect_to_relays(relays):
    relays = relays.split(',')
    for relay in relays:
        await connect_to_relay(relay)

# Connect to remote relay via websocket and query for events
async def connect_to_relay(relay):
    logger.info(f"Connecting to relay at {relay}...")
    async with websockets.connect(relay, ping_interval=ping_keepalive) as relay_conn:
        logger.info(f"Connected to {relay}")

        # Send a REQ message to subscribe to note events only (for now) from past X days
        logger.info("Subscribing to event types = 1")
        search_filter = {
            "kinds": [1],
            "since": int(time.mktime((datetime.datetime.now() - datetime.timedelta(days=search_days)).timetuple())),
            "until": int(time.time())
        }
        await relay_conn.send(json.dumps(["REQ", "nostr-security-scanner", search_filter]))

        logger.info(f"Gathering data from {relay}...")
        while True:
            try:
                event = await asyncio.wait_for(relay_conn.recv(), timeout=relay_timeout)
                event = json.loads(event)
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
    # Check if an event with the same id already exists in the database
    event_id = event[2]["id"]
    existing_event = events_collection.find_one({"event.id": event_id})
    if existing_event:
        logger.debug(f"Event with id {event_id} already exists in the database")
        return
    else:
        # Convert event list into a dictionary and store in database
        event_dict = {"event": event[2], "score": 0, "scored": False}
        try:
            events_collection.insert_one(event_dict)
            logger.debug("Event written to mongodb")
        except Exception as e:
            logger.debug(f"Could not write event to mongodb - {e}")
            return

def check_events(rules):
    # Query unscored events from the events collection
    unscored_events = events_collection.find({"scored": False})

    # Iterate through the unscored events
    logger.info("Checking and scoring unscored events")
    for event in unscored_events:
        # Set default score to start with
        score = 0
        # Get the event content
        event_content = event["event"]["content"]
        event_timestamp = event["event"]["created_at"]
        event_pubkey = event["event"]["pubkey"]
        # Evaluate the event against the ruleset
        for rule in rules:
            description = rules[rule]["description"]
            value = rules[rule]["value"]
            window = rules[rule]["window"]
            weight = rules[rule]["weight"]
            regex = rules[rule]["regex"]

            ## Default System Rules

            # 001 - Malformed/Bad Event Signature
            if rule == "001":
                #logger.info("Rule 001 - Malformed/Bad Event Signature")
                score += 1

            # 002 - Duplicate Event Content
            if rule == "002":
                #logger.info("Rule 002 - Duplicate Event Content")
                # Check if the event content has only 1 or 2 emoji (reactions)
                if all(ord(c) > 127 for c in event_content) and len(event_content) <= 2:
                    # Drop the event
                    return
                else:
                    duplicate_events = events_collection.find({"event.pubkey": event_pubkey, "event.content": event_content})
                    duplicate_count = len(list(duplicate_events))
                    if duplicate_count >= value:
                        # Duplicate content found and is above threshold
                        logger.info(f"Duplicate content found: {event_pubkey} - {event_content} - {duplicate_count} times")
                        score += weight

            # 003 - Large burst of messages
            if rule == "003":
                #logger.info("Rule 003 - Large burst of messages")

                if event_pubkey in pubkey_burst:
                    time_since_last_event = event_timestamp - pubkey_burst[event_pubkey]["last_event_timestamp"]
                    if time_since_last_event <= window:
                        pubkey_burst[event_pubkey]["event_count"] += 1
                        if pubkey_burst[event_pubkey]["event_count"] > value:
                            logger.info(f"Burst content found: {event_pubkey} - {pubkey_burst[event_pubkey]['event_count']} times in {window} seconds")
                            score += weight
                    else:
                        # reset event_count if the time_since_last_event is greater than the window time
                        pubkey_burst[event_pubkey]["event_count"] = 1
                else:
                    pubkey_burst[event_pubkey] = {"event_count": 1, "last_event_timestamp": event_timestamp}

            ## 004 to 0999 - General regex rules

            # else:
            #     #logger.info("Other Regex Rules")
            #     # if re.search(str(event_content), str(regex)):
            #     #      score += weight
            #     #      print(f"004 Match: {event_content}")

            #     #regex = re.compile(regex)
            #     compiled_regex = re.compile(regex, re.IGNORECASE)

            #     if re.search(compiled_regex, event_content):
            #         score += weight
            #         print(f"{rule} Match\n{description}\n: {event_content}")
            #     #if re.search(spam_rules["003"]["regex"], event_content):

        # If the score is above the minimum score, set the score in the events collection and set the "scored" boolean to True
        if score >= 0:
            events_collection.update_one({"event.id": event['event']['id']}, {"$set": {"score": score, "scored": True}})
        # If the score is below the minimum score, set the "scored" boolean to True
        else:
            events_collection.update_one({"event.id": event['event']['id']}, {"$set": {"score": 0, "scored": True}})


# Main program loop
if __name__ == "__main__":
    try:
        asyncio.run(connect_to_relays(relays))
        check_events(ruleset)
        logger.info("The program has finished.")
    except Exception as e:
        logger.critical(f"Exception: {e}")
