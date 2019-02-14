########################################
### Provider Settings ##################
########################################

provider "aws" {
    region  = "${lookup(var.global,"region")}"
    profile = "default"
}
