# terraform/providers.tf
terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "6.30.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
  #   credentials = file(var.service_account_key)
  # Do not hardcode credentials here
  # Use GOOGLE_APPLICATION_CREDENTIALS environment variable instead
}
