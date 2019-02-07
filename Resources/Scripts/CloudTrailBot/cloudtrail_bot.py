#!/usr/bin/env python

import json

def lambda_handler(event, context):
    print(
        json.dumps(event, indent=4)
    )
