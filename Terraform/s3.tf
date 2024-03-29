resource "aws_s3_bucket" "cloudtrail_logs" {
    bucket        = local.cloudtrail_bucket_name
    force_destroy = true

    policy = <<-POLICY
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
                "Resource": "arn:aws:s3:::${local.cloudtrail_bucket_name}"
            },
            {
                "Sid": "",
                "Effect": "Allow",
                "Principal": {
                  "Service": "cloudtrail.amazonaws.com"
                },
                "Action": "s3:PutObject",
                "Resource": "arn:aws:s3:::${local.cloudtrail_bucket_name}/*",
                "Condition": {
                    "StringEquals": {
                        "s3:x-amz-acl": "bucket-owner-full-control"
                    }
                }
            }
        ]
    }
    POLICY

    tags = local.tags
}

resource "aws_s3_bucket_notification" "cloudtrail_logs" {
    bucket = aws_s3_bucket.cloudtrail_logs.id

    lambda_function {
        lambda_function_arn = aws_lambda_function.cloudtrail_bot.arn
        events              = [
            "s3:ObjectCreated:*"
        ]
    }
}
