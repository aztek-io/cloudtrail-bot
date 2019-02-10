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
        cleanup     = "False"
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
        "^CreateLogStream$",
        "^RenewRole$"
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
    bucket_name = "security.${data.aws_iam_account_alias.current.account_alias}.logs"
}

