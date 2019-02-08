#!/usr/bin/env python

import logging
import os
import sys
import json
import re
import requests

#######################################
### Logging Settings ##################
#######################################

logger = logging.getLogger()
logger.setLevel(logging.INFO)

#######################################
### Global Vars #######################
#######################################

true    = True
false   = False
null    = None

SLACK_CHANNEL   = os.environ['SLACK_CHANNEL']
SLACK_WEBHOOK   = os.environ['SLACK_WEBHOOK']
ICON_EMOJI      = ':cloudtrail:'
USERNAME        = 'CloudTrail Bot'

#######################################
### Main Function #####################
#######################################

def main(event, context):
    # logger.info('Event: {}'.format(json.dumps(event, indent=4)))

    ignore_list = ['^Describe', '^List', '^Get']

    logger.info(ignore_list)

    note_worthy_events = parse_event(event, ignore_list)

    for n in note_worthy_events:
        payload = create_slack_payload(n)
        post_to_slack(payload)


def error(message, code=1):
    logger.error(message)
    sys.exit(code)


def parse_event(event, ignore_list):
    note_worthy_events = list()

    for event in event['Records']:
        simplified_event = create_simplified_event(event)

        ignore_logic = None

        logger.info('action: {}'.format(simplified_event['eventName']))

        for i in ignore_list:
            if re.match(i, simplified_event['eventName']):
                logger.info('ignoring: {}'.format(i))
                ignore_logic = True

        if not ignore_logic:
            logger.info('Appending. ignore_logic: {}'.format(ignore_logic))
            note_worthy_events.append(simplified_event)
        else:
            logger.info('Not appending.  ignore_logic: {}'.format(ignore_logic))


    logger.info(json.dumps(note_worthy_events, indent=4))

    return note_worthy_events


def create_simplified_event(event):
    try:
        user = event['userIdentity']['principalId']
    except KeyError:
        user = event['userIdentity']['invokedBy']

    try:
        action      = event['eventName']
        event_time  = event['eventTime']
        resources   = event['resources']
    except KeyError:
        error('Parsing error: {}'.format(json.dumps(event, indent=4)))

    simplified_event = {
        'invokedBy': user,
        'eventTime': event_time,
        'eventName': action,
        'resources': resources
    }

    return simplified_event


def create_slack_payload(json_dict, color='#FF8800', reason='New Cloud Trail Event.'):
    logger.info('Creating slack payload from the following json: {}'.format(json_dict))

    payload ={
        "attachments": [
           {
                "fallback": reason,
                "color": color,
                "title": reason,
                "title_link": "https://us-west-2.console.aws.amazon.com/cloudtrail/home?region=us-west-2#/events",
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
                        "value": '```{}```'.format(json.dumps(json_dict['resources'], indent=4)),
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
    logger.info('POST-ing payload: {}'.format(payload))

    try:
        req = requests.post(SLACK_WEBHOOK, data=json.dumps(payload))
        logger.info("Message posted to {}".format(payload['channel']))
    except requests.exceptions.Timeout as e:
        error("Server connection failed: {}".format(e.reason))
    except requests.exceptions.RequestException as e:
        error("Request failed: {} {}".format(e.status_code, e.reason))

    if req.status_code != 200:
        error("Non 200 status code: {}\n{}\n{}".format(req.status_code, req.headers, req.text))


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
        "Records":[
            {
                "userIdentity":{
                    "type":"AWSService",
                    "invokedBy":"autoscaling.amazonaws.com"
                },
                "eventTime":"2019-02-07T01:29:57Z",
                "eventSource":"sts.amazonaws.com",
                "eventName":"AssumeRole",
                "awsRegion":"us-west-2",
                "sourceIPAddress":"autoscaling.amazonaws.com",
                "userAgent":"autoscaling.amazonaws.com",
                "requestParameters":{
                    "roleArn":"arn:aws:iam::123456789012:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling",
                    "roleSessionName":"AutoScaling",
                    "durationSeconds":1800
                },
               "resources":[
                    {
                        "ARN":"arn:aws:iam::123456789012:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling",
                        "accountId":"123456789012",
                        "type":"AWS::IAM::Role"
                    }
                ],
                "recipientAccountId":"123456789012",
                "sharedEventID":"d910b38d-8a76-4568-9a8f-789a63b722d6"
            }
        ]
    }

    main(event, None)
