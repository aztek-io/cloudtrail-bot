terraform {
    backend "s3" {
        bucket  = "aztek.terraform.tfstate"
        key     = "cloudtrail_bot/terraform.tfstate"
        region  = "us-west-2"
        encrypt = "true"
        profile = "default"
    }
}
