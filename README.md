# CloudTrail Bot

## Why use this?

Have you ever had a co-worker that insisted on manual configurations to changes outside of IaC?

That's why I wrote this lambda function.

## How does it work?

A cloudtrail is is created loging json.gz files to a s3 bucket.  A lambda is triggered on new s3 object creation, and relevent events are pushed to Slack.

## How do I install it in my Environment?

Checkout .gitlab-ci.yml for current build steps.  Don't forget to create secrets.tf if you're not using GitLab.
