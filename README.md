```shell
# Install DEPS
brew install tflint tfsec

# Set the environment variable for GCP authentication
export GOOGLE_APPLICATION_CREDENTIALS="$(pwd)/focust-dev-372a960cb6e6.json"

# Get the email of your service account
SERVICE_ACCOUNT=$(cat focust-dev-372a960cb6e6.json | jq -r '.client_email')

# This tells Terraform and Google Cloud SDK where to find your service account credentials
gcloud auth login

# Set the project name
gcloud config set project focust-dev

# Enables Cloud Resource Manager API, IAM API, Compute Engine API, Service Usage API, Vision API.
gcloud services enable cloudresourcemanager.googleapis.com iam.googleapis.com compute.googleapis.com serviceusage.googleapis.com vision.googleapis.com --project=focust-dev

# Grant necessary roles to your service account
gcloud projects add-iam-policy-binding focust-dev \
  --member="serviceAccount:infrastructure@focust-dev.iam.gserviceaccount.com" \
  --role="roles/compute.admin"

gcloud projects add-iam-policy-binding focust-dev \
  --member="serviceAccount:infrastructure@focust-dev.iam.gserviceaccount.com" \
  --role="roles/iam.serviceAccountAdmin"

gcloud projects add-iam-policy-binding focust-dev \
  --member="serviceAccount:infrastructure@focust-dev.iam.gserviceaccount.com" \
  --role="roles/iam.serviceAccountKeyAdmin"

gcloud projects add-iam-policy-binding focust-dev \
  --member="serviceAccount:infrastructure@focust-dev.iam.gserviceaccount.com" \
  --role="roles/resourcemanager.projectIamAdmin"

gcloud projects add-iam-policy-binding focust-dev \
  --member="serviceAccount:infrastructure@focust-dev.iam.gserviceaccount.com" \
  --role="roles/serviceusage.serviceUsageAdmin"

gcloud storage buckets add-iam-policy-binding gs://focust-dev-infrastructure-state \
    --member="serviceAccount:infrastructure@focust-dev.iam.gserviceaccount.com" \
    --role="roles/storage.objectAdmin"

gcloud projects add-iam-policy-binding focust-dev \
    --member="serviceAccount:infrastructure@focust-dev.iam.gserviceaccount.com" \
    --role="roles/storage.admin"

gcloud projects add-iam-policy-binding focust-dev \
  --member="serviceAccount:infrastructure@focust-dev.iam.gserviceaccount.com" \
  --role="roles/serviceusage.apiKeysAdmin"

gcloud projects add-iam-policy-binding focust-dev \
  --member="serviceAccount:infrastructure@focust-dev.iam.gserviceaccount.com" \
  --role="roles/secretmanager.admin"

# Get latest server password
gcloud secrets versions access latest --secret="focust-server-password" --project="focust-dev"

# Security checks
tfsec --exclude-path .terraform .

# Static Code Analysis tool
tflint

# Initialize Terraform
# This downloads providers, sets up the backend, and prepares your working directory
terraform init

# Preview changes before applying
# This shows what resources will be created, modified, or destroyed
terraform plan

# Apply the changes to create/update the infrastructure
# This will prompt for confirmation before making any changes
terraform apply
# OR
terraform apply -auto-approve

# Removing Old Host Key Entries
ssh-keygen -R VM_IP

# DISCLAIMER: Consider Using terragrunt (TODO)
# It eliminates DRY code & Manual creation of the state bucket.

# NOTE: Create the private & public key in the terraform directory.
```
