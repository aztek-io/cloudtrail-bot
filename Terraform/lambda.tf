########################################
### Lambda Configs: ####################
########################################

# cloudtrail_bot
####################

resource "aws_lambda_function" "cloudtrail_bot" {
    s3_bucket       = "${local.archives_bucket_name}"
    s3_key          = "cloudtrail_bot.zip"
    function_name   = "CloudTrailBot"
    role            = "${aws_iam_role.lambda_cloudtrail_bot.arn}"
    handler         = "cloudtrail_bot.lambda_handler"
    runtime         = "python3.7"
    memory_size     = 128
    timeout         = 5
    environment {
        variables   = {
            SLACK_WEBHOOK           = "${lookup(var.secret,"slack_webhook")}"
            SLACK_CHANNEL           = "${lookup(var.secret,"slack_channel")}"
            EVENT_IGNORE_LIST       = "${jsonencode(var.event_ignore_list)}"
            USER_IGNORE_LIST        = "${jsonencode(var.user_ignore_list)}"
            SOURCE_IGNORE_LIST        = "${jsonencode(var.source_ignore_list)}"
            IGNORE_CLOUDFORMATION   = "Unset to not ignore."
        }
    }

    tags {
        Application = "${lookup(var.global,"application")}"
        Environment = "${lookup(var.global,"environment")}"
        Project     = "${lookup(var.global,"project")}"
        AutoCleanup = "${lookup(var.global,"autocleanup")}"
        IaC         = "${lookup(var.global,"IaC")}"
    }
}

resource "aws_lambda_permission" "cloudtrail_bot" {
    # statement_id    = "AllowExecutionFromS3Bucket"
    action          = "lambda:InvokeFunction"
    function_name   = "${aws_lambda_function.cloudtrail_bot.arn}"
    principal       = "s3.amazonaws.com"
    source_arn      = "${aws_s3_bucket.cloudtrail_logs.arn}"
}

