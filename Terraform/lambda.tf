########################################
### Lambda Functions ###################
########################################

# cloudtrail_bot
####################

resource "aws_lambda_function" "cloudtrail_bot" {
    s3_bucket       = local.archives_bucket_name
    s3_key          = "cloudtrail_bot.zip"
    function_name   = local.app_name
    role            = aws_iam_role.cloudtrail_bot.arn
    handler         = "cloudtrail_bot.lambda_handler"
    runtime         = "python3.7"
    memory_size     = 128
    timeout         = 5
    environment {
        variables   = {
            SLACK_WEBHOOK       = var.webhook
            SLACK_CHANNEL       = var.channel
            EVENT_IGNORE_LIST   = jsonencode(var.event_ignore_list)
            EVENT_ALERT_LIST    = jsonencode(var.event_always_alert_list)
            USER_IGNORE_LIST    = jsonencode(var.user_ignore_list)
            SOURCE_IGNORE_LIST  = jsonencode(var.source_ignore_list)
        }
    }

    tags = local.tags
}

resource "aws_lambda_permission" "cloudtrail_bot" {
    action          = "lambda:InvokeFunction"
    function_name   = aws_lambda_function.cloudtrail_bot.arn
    principal       = "s3.amazonaws.com"
    source_arn      = aws_s3_bucket.cloudtrail_logs.arn
}

