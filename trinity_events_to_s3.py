#!/usr/bin/env python

import base64
import boto3
import certifi
import datetime
import dateutil
from getpass import getpass
import hashlib
import json
import logging
import logging.config
import os
import requests
import sys
import time


# For a custom CA; if no custom CA is used, comment out this line.
certifi.where = lambda: '/etc/pki/tls/cert.pem'

# Configure logging
with open(os.path.join(os.path.dirname(__file__), './logging.json')) as fp:
    logging_config = json.load(fp)
    logging.config.dictConfig(logging_config)

config = {}
# Provide global access to args/config
config_file = os.path.join(os.path.dirname(__file__), './config.json')
with open(config_file, 'r') as config_fp:
    config = json.load(config_fp)

logger = logging.getLogger(__name__)

TRINITY_PORTAL_API_URL = config['trinity_cyber_portal']['api_url']
TRINITY_PORTAL_CLIENT_ID = config['trinity_cyber_portal']['client_id']
MARKER_FILE_DIR = config['trinity_cyber_portal']['marker_file_directory']
MARKER_FILE = config['trinity_cyber_portal']['marker_file']
MARKER_PATH = os.path.expanduser(os.path.join(MARKER_FILE_DIR, MARKER_FILE))

# AWS credentials in ~/.aws/credentials or similar; see S3 boto documentation for options
S3_BUCKET = config['s3']['s3_bucket']
S3_REGION = config['s3']['s3_region']
KEY_BASE = config['s3']['key_base']
KEY_FILE_PREFIX = config['s3']['key_file_prefix']
FAIL_SLEEP_MS = config['s3']['retry_delay_ms']

if KEY_FILE_PREFIX and KEY_FILE_PREFIX[-1] != '-':
    KEY_FILE_PREFIX = KEY_FILE_PREFIX + '-'
else
    KEY_FILE_PREFIX = ''

if not KEY_BASE or len(KEY_BASE) == 0:
    KEY_BASE = '/'
elif KEY_BASE != '/':
    if KEY_BASE[0] == '/':
        KEY_BASE = KEY_BASE[1:]
    if not KEY_BASE[-1] == '/':
        KEY_BASE = KEY_BASE + '/'

graphql_query = """
query AttUsafOtaEvents($after: String) {
  events(first: 1000, after: $after) {
    pageInfo {
      hasNextPage
      endCursor
    }
    edges {
      cursor
      node {
        id
        actionTime
        source
        destination
        sourcePort
        destinationPort
        transportProtocol
        formulaMatches {
            action {
                response
            } 
            formula {
              formulaId
              title
              background
              tags {
                category
                value
              }
            }
        }
        applicationProtocol
        applicationData {
          ... on HttpRequestData {
            method
            path
            host
            userAgent
          }
          ... on HttpResponseData {
            statusCode
            statusString
            server
            contentType
          }
          ... on DnsData {
            host
          }
          ... on TlsData {
            sniHost
          }
        }
      }
    }
  }
}
"""

def get_api_key():
    api_key = None
    if 'TC_API_KEY' in os.environ:
        api_key = os.environ['TC_API_KEY'];
    if not api_key and 'api_key' in config['trinity_cyber_portal']:
        api_key = config['trinity_cyber_portal']['api_key']
    if not api_key:
        api_key = getpass("Please enter your Trinity Cyber customer portal API key: ")
    return api_key

def get_events():
    """Returns a generator that iterates over all events since the marker"""
    api_key = get_api_key()
    https_session = requests.Session()
    https_session.headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer {}'.format(api_key)
    }
    if TRINITY_PORTAL_CLIENT_ID:
        https_session.headers['X-Effective-Client-Ids'] = f'{TRINITY_PORTAL_CLIENT_ID}'
    after_marker = None
    have_more_pages = True
    while have_more_pages:
        if os.path.isfile(MARKER_PATH):
            with open(MARKER_PATH, 'r') as marker_file:
                after_marker = marker_file.read()
        variables = {
            'after': after_marker
        }
        submission_data = {'query': graphql_query, 'variables': variables}
        result = https_session.post(TRINITY_PORTAL_API_URL, json=submission_data)
        result.raise_for_status()
        result_json = result.json()
        if result_json['data']['events']['pageInfo']['endCursor'] is not None:
            for edge in result_json['data']['events']['edges']:
                node = edge['node']
                node['cursor'] = edge['cursor']
                yield node
        have_more_pages = result_json['data']['events']['pageInfo']['hasNextPage']

def upload_event(client, event):
    success = False
    cursor = event['cursor']
    del event['cursor']
    while (not success):
        try:
            upstart = datetime.datetime.now()
            event_time = dateutil.parser.parse(event['actionTime'])
            event_id_b64 = base64.b64encode(event["id"].encode('ISO-8859-1')).decode('ISO-8859-1')
            key = key = f'{KEY_BASE}{event_time.year:04d}/{event_time.month:02d}/{event_time.day:02d}/{KEY_FILE_PREFIX}-{event_id_b64}.json'
            event_bytes = json.dumps(event).encode('UTF-8')
            client.put_object(Bucket=S3_BUCKET, Key=key, Body=event_bytes)
            upend = datetime.datetime.now()
            updur = (upend - upstart)
            logger.info(f'Uploaded {event["actionTime"]}::{event["id"]} in {updur} to s3://{S3_BUCKET}/{key}')
            success = True
            with open(MARKER_PATH, 'w+') as marker_file:
                marker_file.write(cursor)
        except KeyboardInterrupt:
            exit(0)
        except Exception as e:
            logger.error(f'Failed to upload event ID {event["id"]}. Waiting {FAIL_SLEEP_MS}ms and trying again. The exception was:\n{e}')
            time.sleep(FAIL_SLEEP_MS/1000)

if __name__ == "__main__":
    tc3path = os.path.expanduser(MARKER_FILE_DIR)
    logger.info(f'Checking if directory {tc3path} exists to hold the after maker file.')
    if not os.path.exists(tc3path):
        logger.info(f'Creating directory {tc3path} to hold the after marker file.')
        os.mkdir(tc3path)
    client = boto3.client('s3', region_name=S3_REGION)
    while True:
        got_events = False
        for event in get_events():
            got_events = True
            upload_event(client, event)
        if not got_events:
            now_time = datetime.datetime.now()
            fmt_time = now_time.isoformat(timespec='milliseconds')
            no_results = {'time': fmt_time, 'status': 'no results', 'result': f'Trinity Cyber Portal check-in at {fmt_time} and did not detect any new events, waiting until next scheduled check-in.'}
            try:
                key = f'{KEY_BASE}{now_time.year:04d}/{now_time.month:02d}/{now_time.day:02d}/no_data_{now_time.hour:02d}{now_time.minute:02d}{now_time.second:02d}'
                client.put_object(Bucket=S3_BUCKET, Key=key, Body=json.dumps(no_results))
            except KeyboardInterrupt:
                exit(0)
            except Exception as e:
                logger.error(f'Failed send "no event" file with error:\n{e}')
            logger.debug(json.dumps(no_results))
            time.sleep(30)
