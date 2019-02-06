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

