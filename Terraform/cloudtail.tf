resource "aws_cloudtrail" "cloudtrail_bot" {
    name                          = "${lookup(var.global, "application")}"
    s3_bucket_name                = "${aws_s3_bucket.cloudtrail_logs.id}"
    s3_key_prefix                 = "prefix"
    include_global_service_events = false
}
