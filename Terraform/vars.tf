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
