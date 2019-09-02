resource "aws_cloudtrail" "cloudtrail_bot" {
    name                          = local.app_name
    s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
    s3_key_prefix                 = "prefix"
    include_global_service_events = true
    enable_log_file_validation    = true
    is_multi_region_trail         = true

    tags = local.tags
}
