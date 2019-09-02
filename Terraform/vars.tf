########################################
### Variables ##########################
########################################

variable "global" {
    type    = "map"
    default = {
        region      = "us-west-2"
    }
}

variable "project" {}
variable "environment" {}
variable "channel" {}
variable "webhook" {}

variable "project_minor" {
    default = "cloudtrail-bot"
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

variable "event_always_alert_list" {
    type    = list(string)
    default = [
        "DetachRolePolicy"
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
    tags = {
        Project = var.project
        Environment = var.environment
        IaC = true
        AutoCleanup = false
        Consulting  = false
    }
    app_name = join("-", [var.project, var.environment, var.project_minor])
}

