#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Description: Use conditions to kill a stream
Author: Blacktwin, Arcanemagus, Samwiseg0, JonnyWong16, DirtyCajunRice

Adding the script to Tautulli:
Tautulli > Settings > Notification Agents > Add a new notification agent >
 Script

Configuration:
Tautulli > Settings > Notification Agents > New Script > Configuration:

 Script Folder: /path/to/your/scripts
 Script File: ./kill_stream.py (Should be selectable in a dropdown list)
 Script Timeout: {timeout}
 Description: Kill stream(s)
 Save

Triggers:
Tautulli > Settings > Notification Agents > New Script > Triggers:

 Check: Playback Start and/or Playback Pause
 Save

Conditions:
Tautulli > Settings > Notification Agents > New Script > Conditions:

 Set Conditions: [{condition} | {operator} | {value} ]
 Save

Script Arguments:
Tautulli > Settings > Notification Agents > New Script > Script Arguments:

 Select: Playback Start, Playback Pause
 Arguments: --jbop SELECTOR --userId {user_id} --username {username}
            --sessionId {session_id} --notify notifierID
            --interval 30 --limit 1200
            --serverName {server_name}
            --plexUrl {plex_url} --posterUrl {poster_url}
            --richColor '#E5A00D'
            --killMessage 'Your message here.'

 Save
 Close
"""
from __future__ import print_function
from __future__ import unicode_literals

from builtins import object
from builtins import str
import os
import sys
import json
import time
import argparse
from datetime import datetime, timezone
import requests
from requests import get as get_request
from requests import Session
from requests.adapters import HTTPAdapter
from requests.exceptions import RequestException

TAUTULLI_URL = ''
TAUTULLI_APIKEY = ''
TAUTULLI_PUBLIC_URL = ''
TAUTULLI_URL = os.getenv('TAUTULLI_URL', TAUTULLI_URL)
TAUTULLI_PUBLIC_URL = os.getenv('TAUTULLI_PUBLIC_URL', TAUTULLI_PUBLIC_URL)
TAUTULLI_APIKEY = os.getenv('TAUTULLI_APIKEY', TAUTULLI_APIKEY)
TAUTULLI_ENCODING = os.getenv('TAUTULLI_ENCODING', 'UTF-8')
VERIFY_SSL = False

if TAUTULLI_PUBLIC_URL != '/':
    # Check to see if there is a public URL set in Tautulli
    TAUTULLI_LINK = TAUTULLI_PUBLIC_URL
else:
    TAUTULLI_LINK = TAUTULLI_URL

SUBJECT_TEXT = "Tautulli has killed a stream."
BODY_TEXT = "Killed session ID '{id}'. Reason: {message}"
BODY_TEXT_USER = "Killed {user}'s stream. Reason: {message}."

SELECTOR = ['stream', 'allStreams', 'paused']

TAUTULLI_ICON = 'https://github.com/Tautulli/Tautulli/raw/master/data/interfaces/default/images/logo-circle.png'


def utc_now_iso():
    """Get current time in ISO format"""
    utcnow = datetime.utcnow()

    return utcnow.isoformat()


def hex_to_int(value):
    """Convert hex value to integer"""
    try:
        return int(value, 16)
    except (ValueError, TypeError):
        return 0


def arg_decoding(arg):
    """Decode args, encode UTF-8"""
    if sys.version_info[0] < 3:
        return arg.decode(TAUTULLI_ENCODING).encode('UTF-8')
    else:
        return arg


def debug_dump_vars():
    """Dump parameters for debug"""
    print('Tautulli URL - ' + TAUTULLI_URL)
    print('Tautulli Public URL - ' + TAUTULLI_PUBLIC_URL)
    print('Verify SSL - ' + str(VERIFY_SSL))
    print('Tautulli API key - ' + TAUTULLI_APIKEY[-4:]
          .rjust(len(TAUTULLI_APIKEY), "x"))


def get_all_streams(tautulli, user_id=None):
    """Get a list of all current streams.

    Parameters
    ----------
    user_id : int
        The ID of the user to grab sessions for.
    tautulli : obj
        Tautulli object.
    Returns
    -------
    objects
        The of stream objects.
    """
    sessions = tautulli.get_activity()['sessions']

    if user_id:
        streams = [Stream(session=s) for s in sessions if s['user_id'] == user_id]
    else:
        streams = [Stream(session=s) for s in sessions]

    return streams


class Tautulli(object):
    def __init__(self, url, apikey, verify_ssl=False, debug=None):
        self.url = url
        self.apikey = apikey
        self.debug = debug

        self.session = Session()
        self.adapters = HTTPAdapter(max_retries=3,
                                    pool_connections=1,
                                    pool_maxsize=1,
                                    pool_block=True)
        self.session.mount('http://', self.adapters)
        self.session.mount('https://', self.adapters)

        # Ignore verifying the SSL certificate
        if verify_ssl is False:
            self.session.verify = False
            # Disable the warning that the request is insecure, we know that...
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def _call_api(self, cmd, payload, method='GET'):
        payload['cmd'] = cmd
        payload['apikey'] = self.apikey

        try:
            response = self.session.request(method, self.url + '/api/v2', params=payload)
        except RequestException as e:
            print("Tautulli request failed for cmd '{}'. Invalid Tautulli URL? Error: {}".format(cmd, e))
            if self.debug:
                traceback.print_exc()
            return

        try:
            response_json = response.json()
        except ValueError:
            print(
                "Failed to parse json response for Tautulli API cmd '{}': {}"
                .format(cmd, response.content))
            return

        if response_json['response']['result'] == 'success':
            if self.debug:
                print("Successfully called Tautulli API cmd '{}'".format(cmd))
            return response_json['response']['data']
        else:
            error_msg = response_json['response']['message']
            print("Tautulli API cmd '{}' failed: {}".format(cmd, error_msg))
            return

    def get_activity(self, session_key=None, session_id=None):
        """Call Tautulli's get_activity api endpoint"""
        payload = {}

        if session_key:
            payload['session_key'] = session_key
        elif session_id:
            payload['session_id'] = session_id

        return self._call_api('get_activity', payload)

    def notify(self, notifier_id, subject, body):
        """Call Tautulli's notify api endpoint"""
        payload = {'notifier_id': notifier_id,
                   'subject': subject,
                   'body': body}

        return self._call_api('notify', payload)

    def terminate_session(self, session_key=None, session_id=None, message=''):
        """Call Tautulli's terminate_session api endpoint"""
        payload = {}

        if session_key:
            payload['session_key'] = session_key
        elif session_id:
            payload['session_id'] = session_id

        if message:
            payload['message'] = message

        return self._call_api('terminate_session', payload)


class Stream(object):
    def __init__(self, session_id=None, user_id=None, username=None, tautulli=None, session=None):
        self.state = None
        self.ip_address = None
        self.session_id = session_id
        self.user_id = user_id
        self.username = username
        self.session_exists = False
        self.tautulli = tautulli

        if session is not None:
            self._set_stream_attributes(session)

    def _set_stream_attributes(self, session):
        for k, v in session.items():
            setattr(self, k, v)

    def get_all_stream_info(self):
        """Get all stream info from Tautulli."""
        session = self.tautulli.get_activity(session_id=self.session_id)
        if session:
            self._set_stream_attributes(session)
            self.session_exists = True
        else:
            self.session_exists = False

    def terminate(self, message=''):
        """Calls Tautulli to terminate the session.

        Parameters
        ----------
        message : str
            The message to use if the stream is terminated.
        """
        self.tautulli.terminate_session(session_id=self.session_id, message=message)

    def terminate_long_pause(self, message, limit, interval):
        """Kills the session if it is paused for longer than <limit> seconds.

        Parameters
        ----------
        message : str
            The message to use if the stream is terminated.
        limit : int
            The number of seconds the session is allowed to remain paused before it
            is terminated.
        interval : int
            The amount of time to wait between checks of the session state.
        """
        start = datetime.now()
        checked_time = 0
        # Continue checking 2 intervals past the allowed limit in order to
        # account for system variances.
        check_limit = limit + (interval * 2)

        while checked_time < check_limit:
            self.get_all_stream_info()

            if self.session_exists is False:
                sys.stdout.write(
                    "Session '{}'  from user '{}' is no longer active "
                    .format(self.session_id, self.username) +
                    "on the server, stopping monitoring.\n")
                return False

            now = datetime.now()
            checked_time = (now - start).total_seconds()

            if self.state == 'paused':
                if checked_time >= limit:
                    self.terminate(message)
                    sys.stdout.write(
                        "Session '{}' from user '{}' has been killed.\n"
                        .format(self.session_id, self.username))
                    return True
                else:
                    time.sleep(interval)

            elif self.state == 'playing' or self.state == 'buffering':
                sys.stdout.write(
                    "Session '{}' from user '{}' has been resumed, "
                    .format(self.session_id, self.username) +
                    "stopping monitoring.\n")
                return False


def discord_notify(webhook_url, json_payload):
    requests.post(webhook_url, json=json_payload)


def get_ip_info(ip_address):
    return get_request(f'http://ip-api.com/json/{ip_address}').json()


def handle_duplicate_streams(server):
    def new_ip_address(ip):
        ip_info = get_ip_info(ip)
        if ip_info["status"] == "fail":
            return {
                "count": 1,
                "location": {
                    "state": "Unknown",
                    "city": "Unknown"
                },
                "isp": "Unknown"
            }
        return {
            "count": 1,
            "location": {
                "state": ip_info["regionName"],
                "city": ip_info["city"]
            },
            "isp": ip_info["isp"]
        }

    streams = get_all_streams(server)
    duplicate_streams = {}
    unique_names = []
    for stream in streams:
        if stream.username in unique_names:
            if stream.username in duplicate_streams:
                duplicate_streams[stream.username].append(stream)
            else:
                duplicate_streams[stream.username] = [stream]
        else:
            unique_names.append(stream.username)
            duplicate_streams[stream.username] = [stream]
    duplicate_streams = {name: streams for name, streams in duplicate_streams.items() if len(streams) > 1}

    # See if the streams are actually duplicates, or if the IPs are the same
    for user in duplicate_streams.copy().keys():
        unique_ips = []
        for index, stream in enumerate(duplicate_streams[user]):
            if duplicate_streams[user][index].ip_address not in unique_ips:
                unique_ips.append(duplicate_streams[user][index].ip_address)
            else:
                del duplicate_streams[user][index]
                if len(duplicate_streams[user]) <= 1:
                    del duplicate_streams[user]

    if duplicate_streams:
        duplicate_stream_info = {}
        for user in duplicate_streams.keys():
            duplicate_stream_info[user] = []
            for index, stream in enumerate(duplicate_streams[user]):
                duplicate_stream_info[user].append(duplicate_streams[user][index].ip_address)

        # Do not send offense messages to Discord if the ips are in the same state and city
        notify_stream_info = duplicate_stream_info.copy()
        keys_to_remove = []
        for user in notify_stream_info.keys():
            locations = []
            for i in range(len(notify_stream_info[user])):
                ip_info = get_ip_info(notify_stream_info[user][i])
                ip_location = [ip_info["regionName"], ip_info["city"]] if ip_info["status"] != "fail" else ["Unknown",
                                                                                                            "Unknown"]
                # Add location info to the ip string, safe now that we are done with it...
                notify_stream_info[user][i] = {
                    notify_stream_info[user][i]: {"state": ip_location[0], "city": ip_location[1]}}
                if ip_location in locations:
                    continue
                else:
                    locations.append(ip_location)

            # Check if all locations are the same. If they are, continue to log but do not notify on discord
            if all(i == locations[0] for i in locations):
                keys_to_remove.append(user)

        # Now, remove the keys that need to be deleted
        for user in keys_to_remove:
            del notify_stream_info[user]
        if notify_stream_info:
            def pretty_discord(data):
                pretty_data = []
                for name, ips in data.items():
                    location_list = ""
                    for index, ip in enumerate(ips):
                        location = list(ip.values())[0]
                        if index == len(ips) - 1:
                            location_list += f"- {location['city']}, {location['state']}"
                        else:
                            location_list += f"- {location['city']}, {location['state']}\n"
                    pretty_data.append(
                        {
                            "name": name,
                            "value": location_list,
                            "inline": False
                        }
                    )
                discord_msg = {
                    "embeds": [
                        {
                            "title": "Concurrent Stream Info",
                            "color": 16711680,
                            "timestamp": f"{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]}+00:00",
                            "thumbnail": {
                                "url": TAUTULLI_ICON
                            },
                            "fields": [data for data in pretty_data]
                        }
                    ]
                }
                return discord_msg

            discord_notify(opts.webhook, pretty_discord(notify_stream_info))
    else:
        return

    with open("concurrent_ips.json") as f:
        stored_data = json.load(f)
    for user, ip_list in duplicate_stream_info.items():
        if user in stored_data:
            stored_data[user]["offenses"] += 1
            for ip_dict in ip_list:
                ip_address = list(ip_dict.keys())[0]  # Extracting IP address
                if ip_address in stored_data[user]["ip_addresses"]:
                    stored_data[user]["ip_addresses"][ip_address]["count"] += 1
                else:
                    stored_data[user]["ip_addresses"][ip_address] = new_ip_address(ip_address)
        else:
            stored_data[user] = {"offenses": 1, "ip_addresses": {}}
            for ip_dict in ip_list:
                ip_address = list(ip_dict.keys())[0]  # Extracting IP address
                stored_data[user]["ip_addresses"][ip_address] = new_ip_address(ip_address)
    with open("concurrent_ips.json", "w") as outfile:
        json.dump(stored_data, outfile, indent=4)
    print("Done!")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Killing Plex streams from Tautulli.")
    parser.add_argument('--jbop', required=True, choices=SELECTOR,
                        help='Kill selector.\nChoices: (%(choices)s)')
    parser.add_argument('--userId', type=int,
                        help='The unique identifier for the user.')
    parser.add_argument('--username', type=arg_decoding,
                        help='The username of the person streaming.')
    parser.add_argument('--sessionId',
                        help='The unique identifier for the stream.')
    parser.add_argument('--webhook', type=str,
                        help='Discord webhhook URL')
    parser.add_argument('--limit', type=int, default=(20 * 60),  # 20 minutes
                        help='The time session is allowed to remain paused.')
    parser.add_argument('--interval', type=int, default=30,
                        help='The seconds between paused session checks.')
    parser.add_argument('--killMessage', nargs='+', type=arg_decoding,
                        help='Message to send to user whose stream is killed.')
    parser.add_argument('--serverName', type=arg_decoding,
                        help='Plex Server Name')
    parser.add_argument("--debug", action='store_true',
                        help='Enable debug messages.')

    opts = parser.parse_args()

    if not opts.sessionId and opts.jbop != 'allStreams':
        sys.stderr.write("No sessionId provided! Is this synced content?\n")
        sys.exit(1)

    if opts.debug:
        # Import traceback to get more detailed information
        import traceback
        # Dump the ENVs passed from tautulli
        debug_dump_vars()

    # Create a Tautulli instance
    tautulli_server = Tautulli(TAUTULLI_URL.rstrip('/'), TAUTULLI_APIKEY, VERIFY_SSL, opts.debug)

    # Create initial Stream object with basic info
    tautulli_stream = Stream(opts.sessionId, opts.userId, opts.username, tautulli_server)

    # Set a default message if none is provided
    if opts.killMessage:
        kill_message = ' '.join(opts.killMessage)
    else:
        kill_message = 'The server owner has ended the stream.'

    if opts.jbop == 'stream':
        tautulli_stream.terminate(kill_message)

    elif opts.jbop == 'allStreams':
        all_streams = get_all_streams(tautulli_server, opts.userId)

        try:
            handle_duplicate_streams(tautulli_server)
        except Exception as e:
            print(f"Exception: {e}")
            discord_notify(opts.webhook, f"Kill Stream Error: {str(e)}")

        for a_stream in all_streams:
            tautulli_server.terminate_session(session_id=a_stream.session_id, message=kill_message)

    elif opts.jbop == 'paused':
        killed_stream = tautulli_stream.terminate_long_pause(kill_message, opts.limit, opts.interval)
