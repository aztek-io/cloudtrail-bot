#!/usr/bin/env python

import logging
import os
import sys
import json
import boto3
import re
import requests
import gzip

#######################################
### Logging Settings ##################
#######################################

logger = logging.getLogger()
logger.setLevel(logging.INFO)

#######################################
### Boto3 Configs #####################
#######################################

s3 = boto3.client('s3')

#######################################
### Global Vars #######################
#######################################

true    = True
false   = False
null    = None

SLACK_CHANNEL           = os.environ['SLACK_CHANNEL']
SLACK_WEBHOOK           = os.environ['SLACK_WEBHOOK']
EVENT_IGNORE_LIST       = json.loads(os.environ['EVENT_IGNORE_LIST'])
EVENT_ALERT_LIST        = json.loads(os.environ['EVENT_ALERT_LIST'])
USER_IGNORE_LIST        = json.loads(os.environ['USER_IGNORE_LIST'])
SOURCE_IGNORE_LIST      = json.loads(os.environ['SOURCE_IGNORE_LIST'])

ICON_EMOJI = ':cloudtrail:'
USERNAME   = 'CloudTrail Bot'

#######################################
### Main Function #####################
#######################################

def main(event, context):
    try:
        logger.info(
            'Checking s3 objects: {}'.format(
                [
                    record['object']['key'] for record in event['Records']
                ]
            )
        )
    except KeyError as e:
        logger.warn(e)
        logger.info('Event: {}'.format(event))

    for e in event['Records']:
        bucket, s3_object   = parse_event(e)
        cloudtrail_event    = get_object_contents(bucket, s3_object)
        note_worthy_events  = parse_cloudtrail_event(cloudtrail_event)

        for n in note_worthy_events:
            payload = create_slack_payload(n)
            post_to_slack(payload)

    logger.info('Exiting Lambda Function.')


#######################################
### Boto3 Configs #####################
#######################################

def fatal(message, code=1):
    logger.critical(message)
    sys.exit(code)


#######################################
### Program Specific Functions ########
#######################################

def parse_event(event):
    bucket = event['s3']['bucket']['name']
    s3_object = event['s3']['object']['key']

    return bucket, s3_object


def get_object_contents(bucket, s3_object):
    logger.info('Pulling Data from s3. for {}/{}'.format(bucket, s3_object))

    resp = s3.get_object(
        Bucket=bucket,
        Key=s3_object
    )

    body = resp['Body'].read()

    contents = json.loads(gzip.decompress(body))

    logger.debug('Object contents retrieved: {}'.format(type(contents)))

    return contents


def parse_cloudtrail_event(cloudtrail_event):
    logger.info('Iterating over CloudTrail Event Records.')
    logger.debug('CloudTrail Event: {}'.format(cloudtrail_event))

    if "Records" in cloudtrail_event:
        note_worthy_events = parse_records(cloudtrail_event)
    else:
        try:
            logger.info('Possible digest object found.')
            logger.info('Digest End Time: {}'.format(cloudtrail_event["digestEndTime"]))
            logger.info('This object is not going to be parsed')
            note_worthy_events = list()
        except KeyError as e:
            fatal('Key not found: {}'.format(e))

    return note_worthy_events


def parse_records(cloudtrail_event):
    note_worthy_events = list()

    for cte in cloudtrail_event['Records']:
        simplified_event = create_simplified_event(cte)

        if not simplified_event:
            continue

        try:
            sourceIP = cte["sourceIPAddress"]

            if re.match('^.*.amazonaws.com$', sourceIP):
                continue
        except:
            pass

        event_logic     = check_list(simplified_event, check_list=EVENT_IGNORE_LIST, key='eventName')
        user_logic      = check_list(simplified_event, check_list=USER_IGNORE_LIST, key='invokedBy')
        source_logic    = check_list(simplified_event, check_list=SOURCE_IGNORE_LIST, key='eventSource')

        logic_list = [
            event_logic,
            user_logic,
            source_logic
        ]

        always_alert = check_list(simplified_event, check_list=EVENT_ALERT_LIST, key='eventName', ignore=False)

        if True not in logic_list or always_alert:
            logger.info('Appending event "{}".'.format(simplified_event['eventName']))
            note_worthy_events.append(simplified_event)

    logger.info('Note worthy events found: {}'.format(note_worthy_events))

    return note_worthy_events


def create_simplified_event(cloudtrail_event):
    try:
        eventSource = cloudtrail_event["eventSource"]
    except KeyError:
        logger.info("Ignoring this event since it was triggered via CloudFormation.")
        eventSource = ''

    try:
        user = cloudtrail_event['userIdentity']['userName']
    except KeyError:
        try:
            principalId = cloudtrail_event['userIdentity']['principalId']
        except KeyError:
            try:
                # this is sloppy and should be cleaned up in the future.
                principalId = ':{}'.format(cloudtrail_event['userIdentity']['invokedBy'])
            except KeyError:
                logger.error(
                    'Unable to determine the user for this event: {}'.format(
                        json.dumps(cloudtrail_event, indent=4)
                    )
                )

                return False

        try:
            user = principalId.split(':')[1]
        except IndexError:
            logger.error('Unable to split principalId: {}'.format(principalId))
            return False

    try:
        resources   = cloudtrail_event['resources']
    except KeyError:
        resources   = cloudtrail_event['requestParameters']

    try:
        action      = cloudtrail_event['eventName']
        event_time  = cloudtrail_event['eventTime']
        region      = cloudtrail_event['awsRegion']
    except KeyError:
        fatal('Parsing error: {}'.format(json.dumps(cloudtrail_event, indent=4)))

    simplified_event = {
        'invokedBy': user,
        'eventTime': event_time,
        'eventName': action,
        'resources': resources,
        'Region': region,
        'eventSource': eventSource
    }

    return simplified_event


def check_list(simplified_event, check_list, key, ignore=True):
    return_logic = None

    for pattern in check_list:
        if re.match(pattern, simplified_event[key]) and ignore:
            logger.info('Ignoring {} attribute "{}" based on the following pattern: {}'.format(key, simplified_event[key], pattern))
            return_logic = True
            break
        elif re.match(pattern, simplified_event[key]) and not ignore:
            logger.info('Adding {} attribute "{}" based on the following pattern "{}"'.format(key, simplified_event[key], pattern))
            return_logic = True
            break

    return return_logic


def create_slack_payload(json_dict, color='#FF8800', reason='New Cloud Trail Event.'):
    logger.info('Creating slack payload from the following json: {}'.format(json_dict))

    payload ={
        "attachments": [
           {
                "fallback": reason,
                "color": color,
                "title": reason,
                "title_link": "https://{}.console.aws.amazon.com/cloudtrail/home?region={}#/events?StartTime={}&EndTime={}".format(
                   json_dict['Region'],
                   json_dict['Region'],
                   json_dict['eventTime'],
                   json_dict['eventTime']
                ),
                "fields": [
                    {
                        "title": "Initiator",
                        "value": json_dict['invokedBy'],
                        "short": False
                    },
                    {
                        "title": "Event Time",
                        "value": json_dict['eventTime'],
                        "short": False
                    },
                    {
                        "title": "Action",
                        "value": json_dict['eventName'],
                        "short": False
                    },
                    {
                        "title": "Resources",
                        "value": '```\n{}\n```'.format(json.dumps(json_dict['resources'], indent=4)),
                        "short": False
                    }
                ]
            }
        ],
        'channel': SLACK_CHANNEL,
        'username': USERNAME,
        'icon_emoji': ICON_EMOJI
    }

    return payload


def post_to_slack(payload):
    logger.info('POST-ing payload: {}'.format(json.dumps(payload,indent=4)))

    try:
        req = requests.post(SLACK_WEBHOOK, data=str(payload), timeout=3)
        logger.info("Message posted to {} using {}".format(payload['channel'], SLACK_WEBHOOK))
    except requests.exceptions.Timeout as e:
        fatal("Server connection failed: {}".format(e))
    except requests.exceptions.RequestException as e:
        fatal("Request failed: {}".format(e))

    if req.status_code != 200:
        fatal(
            "Non 200 status code: {}\nResponse Headers: {}\nResponse Text: {}".format(
                req.status_code,
                req.headers,
                json.dumps(req.text, indent=4)
            ),
            code=255
        )


#######################################
### Execution #########################
#######################################

def lambda_handler(event, context):
    main(event, context)


if __name__ == '__main__':
    stream = logging.StreamHandler(sys.stdout)

    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    stream.setFormatter(formatter)

    logger.addHandler(stream)

    event = {
        "Records": [
            {
                "awsRegion": "us-west-2",
                "eventTime": "2019-02-08T13:46:44.679Z",
                "eventName": "ObjectCreated:Put",
                "s3": {
                    "bucket": {
                        "name": "security.aztek.logs",
                        "arn": "arn:aws:s3:::security.aztek.logs"
                    },
                    "object": {
                        "key": "prefix/AWSLogs/976168295228/CloudTrail-Digest/eu-west-2/2019/09/02/976168295228_CloudTrail-Digest_eu-west-2_CloudTrailBot_us-west-2_20190902T120445Z.json.gz"
                    }
                }
            }
        ]
    }

    main(event, None)
