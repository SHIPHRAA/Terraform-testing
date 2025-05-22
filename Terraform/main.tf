# Define a base script with common functionality
locals {
  password_setup_script = <<-EOF
    # Set up the user password
    echo "${var.ssh_username}:${random_password.server_password.result}" | chpasswd

    # Configure password authentication in SSH main config
    sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/g' /etc/ssh/sshd_config
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/g' /etc/ssh/sshd_config

    # Also check and fix cloud image settings that might override the main config
    if [ -f /etc/ssh/sshd_config.d/60-cloudimg-settings.conf ]; then
      sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/g' /etc/ssh/sshd_config.d/60-cloudimg-settings.conf
    fi

    # Check for any other sshd_config.d files that might disable password auth
    for config_file in /etc/ssh/sshd_config.d/*.conf; do
      if [ -f "$config_file" ]; then
        sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/g' "$config_file"
      fi
    done

    # Restart SSH service to apply changes
    systemctl restart sshd
  EOF

  # Base startup script with all common configuration
  base_vm_startup_script = <<-EOF
    #!/bin/bash
    # Update system
    apt-get update
    apt-get upgrade -y

    # Install Docker
    curl -fsSL https://get.docker.com -o get-docker.sh
    sh get-docker.sh

    # Install Docker Compose
    curl -L "https://github.com/docker/compose/releases/download/v2.20.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose

    # Setup Docker credentials for GitHub Container Registry
    # Create directory for Docker config
    mkdir -p /home/${var.ssh_username}/.docker

    # Create Docker config file with authentication
    cat > /home/${var.ssh_username}/.docker/config.json << 'DOCKER_CONFIG'
    {
      "auths": {
        "ghcr.io": {
          "auth": "${var.ghcr_auth_token}"
        }
      }
    }
    DOCKER_CONFIG

    # Set correct ownership and permissions
    chown -R ${var.ssh_username}:${var.ssh_username} /home/${var.ssh_username}/.docker
    chmod 700 /home/${var.ssh_username}/.docker
    chmod 600 /home/${var.ssh_username}/.docker/config.json

    # Also create a root Docker config for system-wide access
    mkdir -p /root/.docker
    cp /home/${var.ssh_username}/.docker/config.json /root/.docker/config.json
    chmod 600 /root/.docker/config.json

    # Install Nginx
    apt-get install -y nginx

    # Update Nginx configuration with clean custom settings
    cat > /etc/nginx/nginx.conf << 'NGINX_CONF_EOF'
    user www-data;
    worker_processes auto;
    pid /run/nginx.pid;
    include /etc/nginx/modules-enabled/*.conf;

    events {
      worker_connections 768;
    }

    http {
      # Basic Settings
      proxy_read_timeout 3600s;
      proxy_connect_timeout 3600s;
      proxy_send_timeout 3600s;
      sendfile on;
      tcp_nopush on;
      tcp_nodelay on;
      keepalive_timeout 3600;
      types_hash_max_size 2048;

      include /etc/nginx/mime.types;
      default_type application/octet-stream;

      # SSL Settings
      ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;
      ssl_prefer_server_ciphers on;

      # Logging Settings
      access_log /var/log/nginx/access.log;
      error_log /var/log/nginx/error.log;

      # Gzip Settings
      gzip on;

      # Virtual Host Configs
      include /etc/nginx/conf.d/*.conf;
      include /etc/nginx/sites-enabled/*;
    }
    NGINX_CONF_EOF

    # Configure clean default Nginx site
    cat > /etc/nginx/sites-available/default << 'NGINX_SITE_EOF'
    server {
      listen 80 default_server;
      listen [::]:80 default_server;

      root /var/www/html;
      index index.html index.htm index.nginx-debian.html;

      server_name _;

      location / {
        try_files $uri $uri/ =404;
      }
    }
    NGINX_SITE_EOF

    # Get the VM's external IP address
    EXTERNAL_IP=$(curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip)

    # Create staging-specific Nginx server.conf using the dynamic IP
    cat > /etc/nginx/conf.d/server.conf << EOF_SERVER_CONF
    server {
        listen 80;
        server_name $EXTERNAL_IP;

        # Proxy requests to the Docker container
        location / {
            proxy_pass http://localhost:3000;
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto \$scheme;
        }

        # Proxy requests to the Docker container
        location /api {
            proxy_pass http://localhost:8000;
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto \$scheme;
        }

        location /v2 {
            proxy_pass http://localhost:8080;
            proxy_http_version 1.1;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection 'upgrade';
            proxy_set_header Host \$host;
            proxy_cache_bypass \$http_upgrade;
        }
    }
    EOF_SERVER_CONF

    # Enable and restart Nginx
    systemctl enable nginx
    systemctl restart nginx

    # Install logrotate
    apt-get install -y logrotate

    # Create Docker log rotation configuration
    cat > /etc/logrotate.d/docker-container-logs << 'LOGROTATE_EOF'
    /var/lib/docker/containers/*/*.log {
        daily
        rotate 7
        compress
        size=50M
        missingok
        delaycompress
        copytruncate
    }
    LOGROTATE_EOF

    # Make sure the config has correct permissions
    chmod 644 /etc/logrotate.d/docker-container-logs

    # Setup Docker cleanup systemd service
    cat > /etc/systemd/system/docker-cleanup.service << 'CLEANUP_EOF'
    [Unit]
    Description=Docker system cleanup service
    After=docker.service
    Requires=docker.service

    [Service]
    Type=oneshot
    ExecStart=/bin/bash -c 'docker system prune -af --volumes; \
                           docker images -f "dangling=true" -q | xargs -r docker rmi -f; \
                           for image in $(docker images "ghcr.io/*/focust-*" --format "{{.Repository}}:{{.Tag}}" | grep -v "latest" | sort -r | tail -n +3); do \
                             docker rmi $image || true; \
                           done; \
                           echo "Docker cleanup completed at $(date)" >> /var/log/docker-cleanup.log'

    [Install]
    WantedBy=multi-user.target
    CLEANUP_EOF

    # Setup timer to run cleanup weekly
    cat > /etc/systemd/system/docker-cleanup.timer << 'TIMER_EOF'
    [Unit]
    Description=Run Docker cleanup service weekly

    [Timer]
    OnCalendar=Sun 02:00:00
    Persistent=true

    [Install]
    WantedBy=timers.target
    TIMER_EOF

    # Enable and start the timer
    systemctl daemon-reload
    systemctl enable docker-cleanup.timer
    systemctl start docker-cleanup.timer

    # Create disk space monitoring script
    cat > /usr/local/bin/monitor-disk-space.sh << 'MONITOR_EOF'
    #!/bin/bash

    THRESHOLD=80
    DOCKER_DIR="/var/lib/docker"

    USAGE=$(df -h $DOCKER_DIR | awk 'NR==2 {print $5}' | sed 's/%//')

    if [ $USAGE -gt $THRESHOLD ]; then
      # Run emergency cleanup
      docker system prune -af --volumes
      docker images -f "dangling=true" -q | xargs -r docker rmi -f

      # Keep only the latest image of each repository and the "latest" tag
      for repo in $(docker images --format "{{.Repository}}" | sort | uniq); do
        # Skip non-project images
        if [[ $repo != ghcr.io/*/focust-* ]]; then
          continue
        fi

        # Get all tags for this repository except "latest"
        tags=$(docker images $repo --format "{{.Tag}}" | grep -v "latest" | sort -r)

        # Keep the first tag, remove the rest
        count=0
        for tag in $tags; do
          if [ $count -gt 0 ]; then
            docker rmi "$repo:$tag" || true
          fi
          count=$((count+1))
        done
      done

      echo "Emergency disk cleanup performed at $(date)" >> /var/log/docker-cleanup.log
    fi
    MONITOR_EOF

    chmod +x /usr/local/bin/monitor-disk-space.sh

    # Setup cron job to check disk space daily
    echo "0 0 * * * /usr/local/bin/monitor-disk-space.sh" | crontab -

    # Configure Docker permissions
    usermod -aG docker ${var.ssh_username}
  EOF

  # Environment-specific scripts that just add the directory creation
  staging_vm_startup_script = <<-EOF
    ${local.base_vm_startup_script}
    ${local.password_setup_script}

    # Create staging-specific app directory
    mkdir -p /home/${var.ssh_username}/fact-check-staging/credentials
    chown -R ${var.ssh_username}:${var.ssh_username} /home/${var.ssh_username}/fact-check-staging
  EOF

  production_vm_startup_script = <<-EOF
    ${local.base_vm_startup_script}
    ${local.password_setup_script}

    # Create production-specific app directory
    mkdir -p /home/${var.ssh_username}/fact-check-prod/credentials
    chown -R ${var.ssh_username}:${var.ssh_username} /home/${var.ssh_username}/fact-check-prod
  EOF
}

# Create static IPs for staging and production
resource "google_compute_address" "staging_ip" {
  name         = "focust-staging-ip"
  region       = var.region
  address_type = "EXTERNAL"
}

resource "google_compute_address" "production_ip" {
  name         = "focust-production-ip"
  region       = var.region
  address_type = "EXTERNAL"
}

# Create firewall rule to allow web traffic
resource "google_compute_firewall" "allow_web" {
  name    = "allow-web-traffic"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["80", "443", "8000", "3000"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["web-server"]
}

# Create firewall rule to allow SSH
resource "google_compute_firewall" "allow_ssh" {
  name    = "allow-ssh"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["ssh-enabled"]
}

# Create staging VM
resource "google_compute_instance" "staging_vm" {
  name         = "focust-staging"
  machine_type = var.machine_type
  zone         = var.zone

  boot_disk {
    initialize_params {
      image = "ubuntu-os-cloud/ubuntu-2204-lts"
      size  = var.boot_disk_size
      type  = var.boot_disk_type
    }
  }

  network_interface {
    network = "default"
    access_config {
      nat_ip = google_compute_address.staging_ip.address
    }
  }

  tags = ["web-server", "ssh-enabled"]

  metadata = {
    ssh-keys = "${var.ssh_username}:${file(var.ssh_public_key_file)}"
  }

  metadata_startup_script = local.staging_vm_startup_script
}

# Create production VM
resource "google_compute_instance" "production_vm" {
  name         = "focust-production"
  machine_type = var.machine_type
  zone         = var.zone

  boot_disk {
    initialize_params {
      image = "ubuntu-os-cloud/ubuntu-2204-lts"
      size  = var.boot_disk_size
      type  = var.boot_disk_type
    }
  }

  network_interface {
    network = "default"
    access_config {
      nat_ip = google_compute_address.production_ip.address
    }
  }

  tags = ["web-server", "ssh-enabled"]

  metadata = {
    ssh-keys = "${var.ssh_username}:${file(var.ssh_public_key_file)}"
  }

  metadata_startup_script = local.production_vm_startup_script
}

# Create GCP Bucket for database backups.
resource "google_storage_bucket" "db_backup_bucket" {
  name                        = var.bucket_name
  location                    = var.region
  force_destroy               = true
  uniform_bucket_level_access = true

  lifecycle_rule {
    condition {
      age            = var.db_snapshot_retention_days
      matches_prefix = ["db_backups/"]
    }
    action {
      type = "Delete"
    }
  }

  versioning {
    enabled = true
  }
}

# Enable the Cloud Vision API
resource "google_project_service" "vision_api" {
  project = var.project_id
  service = "vision.googleapis.com"

  # Disable dependent services when this service is disabled
  disable_dependent_services = true
  # Don't disable the service if it was already enabled before Terraform
  disable_on_destroy = false
}

# Create a service account for Vision API access
resource "google_service_account" "vision_service_account" {
  account_id   = "vision-api-service-account"
  display_name = "Vision API Service Account"
  project      = var.project_id
  description  = "Service account for accessing Cloud Vision API"

  # Depend on API being enabled first
  depends_on = [google_project_service.vision_api]
}

# Grant the service account the proper role to use Vision API
resource "google_project_iam_member" "vision_api_user" {
  project = var.project_id
  role    = "roles/aiplatform.user"
  member  = "serviceAccount:${google_service_account.vision_service_account.email}"
}

# Create a service account key for application use
resource "google_service_account_key" "vision_sa_key" {
  service_account_id = google_service_account.vision_service_account.name
}

# Store the Vision API service account key in your bucket in a dedicated folder
resource "google_storage_bucket_object" "vision_sa_key_file" {
  name    = "service_keys/vision-api-key.json"
  bucket  = google_storage_bucket.db_backup_bucket.name
  content = base64decode(google_service_account_key.vision_sa_key.private_key)
}

# Enable the API Keys API first
resource "google_project_service" "apikeys_api" {
  project = var.project_id
  service = "apikeys.googleapis.com"

  # Disable dependent services when this service is disabled
  disable_dependent_services = true
  # Don't disable the service if it was already enabled before Terraform
  disable_on_destroy = false
}

# Enable the Google Maps API services
resource "google_project_service" "maps_api" {
  project = var.project_id
  service = "maps-backend.googleapis.com"

  # Disable dependent services when this service is disabled
  disable_dependent_services = true
  # Don't disable the service if it was already enabled before Terraform
  disable_on_destroy = false

  depends_on = [google_project_service.apikeys_api]
}

# Enable the Geocoding API
resource "google_project_service" "geocoding_api" {
  project = var.project_id
  service = "geocoding-backend.googleapis.com"

  disable_dependent_services = true
  disable_on_destroy         = false

  depends_on = [google_project_service.maps_api]
}

# Create a service account for Maps API access
resource "google_service_account" "maps_service_account" {
  account_id   = "maps-api-service-account"
  display_name = "Maps API Service Account"
  project      = var.project_id
  description  = "Service account for accessing Google Maps APIs"

  # Depend on API being enabled first
  depends_on = [
    google_project_service.maps_api,
    google_project_service.geocoding_api
  ]
}

# Grant the service account the proper role to use Maps APIs
resource "google_project_iam_member" "maps_api_user" {
  project = var.project_id
  role    = "roles/serviceusage.serviceUsageConsumer"
  member  = "serviceAccount:${google_service_account.maps_service_account.email}"
}

# Create an API key for Maps services
resource "google_apikeys_key" "maps_api_key" {
  name         = "maps-api-key"
  display_name = "Maps API Key"
  project      = var.project_id

  restrictions {
    api_targets {
      service = "maps-backend.googleapis.com"
    }

    api_targets {
      service = "geocoding-backend.googleapis.com"
    }

    # browser_key_restrictions {
    #   allowed_referrers = [
    #     "https://${google_compute_address.staging_ip.address}/*",
    #     "https://${google_compute_address.production_ip.address}/*"
    #   ]
    # }
  }

  depends_on = [
    google_project_service.apikeys_api,
    google_project_service.maps_api,
    google_project_service.geocoding_api
  ]
}

# Create a service account key for application use
resource "google_service_account_key" "maps_sa_key" {
  service_account_id = google_service_account.maps_service_account.name
}

# Store the Maps API service account key in your bucket
resource "google_storage_bucket_object" "maps_sa_key_file" {
  name    = "service_keys/maps-api-key.json"
  bucket  = google_storage_bucket.db_backup_bucket.name
  content = base64decode(google_service_account_key.maps_sa_key.private_key)
}

# Store the API key in a separate file for easy retrieval
resource "google_storage_bucket_object" "maps_api_key_file" {
  name    = "service_keys/maps-api-key.txt"
  bucket  = google_storage_bucket.db_backup_bucket.name
  content = google_apikeys_key.maps_api_key.key_string
}

resource "google_secret_manager_secret_iam_member" "server_secret_accessor" {
  project   = var.project_id
  secret_id = google_secret_manager_secret.server_password.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:infrastructure@focust-dev.iam.gserviceaccount.com"
}

# Create a password that change between Terraform runs
resource "random_password" "server_password" {
  length           = 16
  special          = true
  override_special = "_%@"
  min_upper        = 1
  min_lower        = 1
  min_numeric      = 1
  min_special      = 1

  # This keepers block ensures the password remains the same
  # even across multiple Terraform applies, unless you explicitly change the keeper value
  # keepers = {
  #   password_version = "1"  # Increment this value to generate a new password
  # }
}

# Store password in Google Secret Manager
resource "google_secret_manager_secret" "server_password" {
  secret_id = "focust-server-password"

  replication {
    auto {
      # This empty block enables automatic replication
    }
  }

  depends_on = [google_project_service.secretmanager_api]
}

resource "google_secret_manager_secret_version" "server_password" {
  secret      = google_secret_manager_secret.server_password.id
  secret_data = random_password.server_password.result
}

# Enable Secret Manager API
resource "google_project_service" "secretmanager_api" {
  project = var.project_id
  service = "secretmanager.googleapis.com"

  disable_dependent_services = true
  disable_on_destroy = false
}
