# terraform/variables.tf
variable "project_id" {
  description = "The GCP project ID"
  type        = string
}

variable "region" {
  description = "The GCP region to deploy resources"
  type        = string
  default     = "asia-northeast1"
}

variable "zone" {
  description = "The GCP zone within the region"
  type        = string
  default     = "asia-northeast1-a"
}

variable "service_account_key" {
  description = "The service account authentication key (JSON)"
  type        = string
  default     = ""
}

variable "bucket_name" {
  description = "The GCS Bucket name."
  type        = string
}

variable "db_snapshot_retention_days" {
  description = "Number of days after which a database snapshot is deleted."
  type        = number
  default     = 30
}

# VM Configuration Variables
variable "machine_type" {
  description = "The machine type for the VMs"
  type        = string
  default     = "e2-medium"
}

variable "boot_disk_size" {
  description = "Boot disk size in GB"
  type        = number
  default     = 50
}

variable "boot_disk_type" {
  description = "Boot disk type"
  type        = string
  default     = "pd-balanced"
}

variable "ssh_username" {
  description = "The SSH username for VM access"
  type        = string
  default     = "focust"
}

variable "ssh_public_key_file" {
  description = "Path to the SSH public key file"
  type        = string
  default     = "~/.ssh/focust_vm_key.pub"
}
variable "ghcr_auth_token" {
  description = "Base64 encoded authentication token for GitHub Container Registry"
  type        = string
}
