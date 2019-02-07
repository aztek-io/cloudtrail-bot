resource "aws_s3_bucket" "foo" {
    bucket        = "logs.${data.aws_iam_account_alias.current.account_alias}"
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
            "Resource": "arn:aws:s3:::logs.${data.aws_iam_account_alias.current.account_alias}"
        },
        {
            "Sid": "",
            "Effect": "Allow",
            "Principal": {
              "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::logs.${data.aws_iam_account_alias.current.account_alias}/*",
            "Condition": {
                "StringEquals": {
                    "s3:x-amz-acl": "bucket-owner-full-control"
                }
            }
        }
    ]
}
POLICY
}
