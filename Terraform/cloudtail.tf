resource "aws_cloudtrail" "cloudtrail_bot" {
    name                          = "${lookup(var.global, "application")}"
    s3_bucket_name                = "${aws_s3_bucket.cloudtrail_logs.id}"
    s3_key_prefix                 = "prefix"
    include_global_service_events = false
    enable_log_file_validation    = true

    tags {
        Application = "${lookup(var.global,"application")}"
        Environment = "${lookup(var.global,"environment")}"
        Project     = "${lookup(var.global,"project")}"
        AutoCleanup = "${lookup(var.global,"autocleanup")}"
        IaC         = "${lookup(var.global,"IaC")}"
    }
}
