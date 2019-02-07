########################################
### Variables ##########################
########################################

variable "global" {
    type    = "map"
    default = {
        region      = "us-west-2"
        application = "CloudTrailBot"
        environment = "Staging"
    }
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

