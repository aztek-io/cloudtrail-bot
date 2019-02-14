########################################
### Variables ##########################
########################################

variable "global" {
    type    = "map"
    default = {
        region      = "us-west-2"
        application = "CloudTrailBot"
        project     = "ChatOps"
        environment = "Development"
        autocleanup = "False"
        IaC         = "True"
    }
}

variable "event_ignore_list" {
    type    = "list"
    default = [
        "^Describe*",
        "^Assume*",
        "^List*",
        "^Get*",
        "^Decrypt*",
        "^Lookup*",
        "^BatchGet*",
        "^CreateLogStream$",
        "^RenewRole$",
        "^REST.GET.OBJECT_LOCK_CONFIGURATION$",
        "TestEventPattern",
        "TestScheduleExpression",
        "CreateNetworkInterface",
        "ValidateTemplate"
    ]
}

variable "user_ignore_list" {
    type    = "list"
    default = [
        "^awslambda_*",
        "^aws-batch$",
        "^bamboo*",
        "^i-*",
        "^[0-9]*$",
        "^ecs-service-scheduler$",
        "^AutoScaling$",
        "^AWSCloudFormation$",
        "^CloudTrailBot$",
        "^SLRManagement$"
    ]
}

variable "source_ignore_list" {
    type    = "list"
    default = [
        "batch.amazonaws.com",
        "config.amazonaws.com"
    ]
}

########################################
### Data Sources #######################
########################################

data "aws_iam_account_alias" "current" {}

########################################
### Variable Interpolation #############
########################################

locals {
    cloudtrail_bucket_name  = "security.${data.aws_iam_account_alias.current.account_alias}.logs"
    archives_bucket_name    = "archives.${data.aws_iam_account_alias.current.account_alias}.io"
}

