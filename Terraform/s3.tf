resource "aws_s3_bucket" "cloudtrail_logs" {
    bucket        = "${local.bucket_name}"
    force_destroy = true

    policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "",
            "Effect": "Allow",
            "Principal": {
              "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:GetBucketAcl",
            "Resource": "arn:aws:s3:::${local.bucket_name}"
        },
        {
            "Sid": "",
            "Effect": "Allow",
            "Principal": {
              "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::${local.bucket_name}/*",
            "Condition": {
                "StringEquals": {
                    "s3:x-amz-acl": "bucket-owner-full-control"
                }
            }
        }
    ]
}
POLICY

    tags {
        Application = "${lookup(var.global,"application")}"
        Environment = "${lookup(var.global,"environment")}"
        Project     = "${lookup(var.global,"project")}"
        AutoCleanup = "${lookup(var.global,"autocleanup")}"
        IaC         = "${lookup(var.global,"IaC")}"
    }
}

resource "aws_s3_bucket_notification" "cloudtrail_logs" {
    bucket = "${aws_s3_bucket.cloudtrail_logs.id}"

    lambda_function {
        lambda_function_arn = "${aws_lambda_function.cloudtrail_bot.arn}"
        events              = [
            "s3:ObjectCreated:*"
        ]
    }
}
