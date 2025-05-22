# terraform/backend.tf
terraform {
  backend "gcs" {
    bucket = "focust-dev-infrastructure-state"
    prefix = "terraform/state"
    # credentials = file(var.service_account_key)
    # Do not hardcode credentials here
    # Use GOOGLE_APPLICATION_CREDENTIALS environment variable instead
  }
}
