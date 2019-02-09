########################################
### IAM Policies #######################
########################################

resource "aws_iam_policy" "lambda_cloudtrail_bot" {
    name    = "lambda_cloudtrail_bot"
    path    = "/"
    policy  = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": "arn:aws:logs:*:*:*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:GetObjectTagging"
            ],
            "Resource": "${aws_s3_bucket.cloudtrail_logs.arn}/*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "lambda:InvokeFunction"
            ],
            "Resource": "*"
        }
    ]
}
POLICY
}


########################################
### IAM Roles ##########################
########################################

resource "aws_iam_role" "lambda_cloudtrail_bot" {
  name = "lambda_cloudtrail_bot"

  assume_role_policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": "sts:AssumeRole",
            "Principal": {
                "Service": "lambda.amazonaws.com"
            },
            "Effect": "Allow",
            "Sid": ""
        }
    ]
}
POLICY
}

########################################
### IAM Policy Attachments #############
########################################

resource "aws_iam_policy_attachment" "lambda_cloudtrail_bot" {
    name            = "lambda_cloudtrail_bot"
    roles           = [
        "${aws_iam_role.lambda_cloudtrail_bot.name}"
    ]
    policy_arn      = "${aws_iam_policy.lambda_cloudtrail_bot.arn}"
}

