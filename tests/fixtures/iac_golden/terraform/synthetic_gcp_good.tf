provider "google" {
  project = "demo"
}

resource "google_storage_bucket" "good" {
  name                        = "corp-good"
  location                    = "US"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
}

resource "google_storage_bucket_iam_member" "ops" {
  bucket = google_storage_bucket.good.name
  role   = "roles/storage.objectViewer"
  member = "group:ops@example.com"
}

resource "google_compute_firewall" "ssh_from_office" {
  name    = "allow-ssh-office"
  network = "default"
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
  source_ranges = ["203.0.113.0/24"]
}

resource "google_compute_firewall" "https" {
  name    = "allow-https"
  network = "default"
  allow {
    protocol = "tcp"
    ports    = ["443"]
  }
  source_ranges = ["0.0.0.0/0"]
  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_firewall" "deny_all" {
  name    = "deny-all"
  network = "default"
  deny {
    protocol = "all"
  }
  source_ranges = ["0.0.0.0/0"]
}

resource "google_compute_firewall" "egress" {
  name      = "egress"
  network   = "default"
  direction = "EGRESS"
  allow {
    protocol = "all"
  }
  destination_ranges = ["0.0.0.0/0"]
}

resource "google_compute_firewall" "disabled" {
  name     = "disabled"
  network  = "default"
  disabled = true
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
  source_ranges = ["0.0.0.0/0"]
}

resource "google_sql_database_instance" "db" {
  name             = "db"
  database_version = "POSTGRES_15"
  settings {
    tier = "db-f1-micro"
    ip_configuration {
      ipv4_enabled    = false
      private_network = "projects/demo/global/networks/default"
      ssl_mode        = "ENCRYPTED_ONLY"
    }
    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
    }
  }
}

resource "google_compute_instance" "vm" {
  name         = "vm"
  machine_type = "e2-medium"
  zone         = "us-central1-a"
  network_interface {
    network = "default"
  }
  metadata = {
    enable-oslogin         = "true"
    block-project-ssh-keys = "true"
  }
}

resource "google_compute_project_metadata" "project" {
  metadata = {
    enable-oslogin = "TRUE"
  }
}

resource "google_compute_subnetwork" "app" {
  name                     = "app"
  ip_cidr_range            = "10.2.0.0/16"
  network                  = "default"
  private_ip_google_access = true
  log_config {
    aggregation_interval = "INTERVAL_10_MIN"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}
