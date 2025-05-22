# terraform/outputs.tf
output "backup_bucket_name" {
  description = "The name of the GCS bucket where backups are stored"
  value       = google_storage_bucket.db_backup_bucket.name
}

output "backup_bucket_url" {
  description = "The URL of the GCS bucket"
  value       = "gs://${google_storage_bucket.db_backup_bucket.name}"
}

output "backup_bucket_self_link" {
  description = "The self_link of the GCS bucket"
  value       = google_storage_bucket.db_backup_bucket.self_link
}

output "staging_ip" {
  description = "The static IP address for staging environment"
  value       = google_compute_address.staging_ip.address
}

output "production_ip" {
  description = "The static IP address for production environment"
  value       = google_compute_address.production_ip.address
}

output "staging_vm_name" {
  description = "The name of the staging VM"
  value       = google_compute_instance.staging_vm.name
}

output "production_vm_name" {
  description = "The name of the production VM"
  value       = google_compute_instance.production_vm.name
}

output "vision_service_account_email" {
  description = "The email address of the service account for Vision API"
  value       = google_service_account.vision_service_account.email
}

output "vision_service_account_key_location" {
  description = "The location of the service account key file for Vision API"
  value       = "gs://${google_storage_bucket.db_backup_bucket.name}/${google_storage_bucket_object.vision_sa_key_file.name}"
}

# Maps API Outputs
output "maps_service_account_email" {
  description = "The email address of the service account for Maps API"
  value       = google_service_account.maps_service_account.email
}

output "maps_service_account_key_location" {
  description = "The location of the service account key file for Maps API"
  value       = "gs://${google_storage_bucket.db_backup_bucket.name}/${google_storage_bucket_object.maps_sa_key_file.name}"
}

output "maps_api_key_location" {
  description = "The location of the Maps API key file"
  value       = "gs://${google_storage_bucket.db_backup_bucket.name}/${google_storage_bucket_object.maps_api_key_file.name}"
}
