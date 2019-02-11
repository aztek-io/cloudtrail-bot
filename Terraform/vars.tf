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
        "^REST.GET.OBJECT_LOCK_CONFIGURATION$"
    ]
}

variable "user_ignore_list" {
    type    = "list"
    default = [
        "^bamboo*",
        "^gitlab*",
        "^i-*",
        "^ecs-service-scheduler$",
        "^AWSCloudFormation$"
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

