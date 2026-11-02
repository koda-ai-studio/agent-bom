provider "google" {
  project = "demo"
}

resource "google_storage_bucket" "logs" {
  name                        = "corp-logs"
  location                    = "US"
  uniform_bucket_level_access = false
}

resource "google_storage_bucket" "default_acls" {
  name     = "corp-default"
  location = "US"
}

resource "google_storage_bucket_iam_member" "public" {
  bucket = google_storage_bucket.logs.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}

resource "google_storage_bucket_iam_binding" "authenticated" {
  bucket  = google_storage_bucket.logs.name
  role    = "roles/storage.objectViewer"
  members = ["allAuthenticatedUsers", "user:ops@example.com"]
}

resource "google_compute_firewall" "ssh" {
  name    = "allow-ssh"
  network = "default"
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
  source_ranges = ["0.0.0.0/0"]
}

resource "google_compute_firewall" "rdp_range" {
  name    = "allow-rdp"
  network = "default"
  allow {
    protocol = "tcp"
    ports    = ["3380-3390"]
  }
  source_ranges = ["10.0.0.0/8", "::/0"]
}

resource "google_compute_firewall" "all" {
  name    = "allow-all"
  network = "default"
  allow {
    protocol = "all"
  }
  source_ranges = ["0.0.0.0/0"]
}

resource "google_compute_firewall" "web" {
  name    = "allow-web"
  network = "default"
  allow {
    protocol = "tcp"
    ports    = ["8080"]
  }
  source_ranges = ["0.0.0.0/0"]
}

resource "google_sql_database_instance" "db" {
  name             = "db"
  database_version = "POSTGRES_15"
  settings {
    tier = "db-f1-micro"
    ip_configuration {
      ipv4_enabled = true
      require_ssl  = false
      authorized_networks {
        value = "0.0.0.0/0"
      }
    }
  }
  root_password = "NotARealPassw0rd-demo"
}

resource "google_sql_database_instance" "db_v6" {
  name             = "db-v6"
  database_version = "POSTGRES_15"
  settings {
    tier = "db-f1-micro"
    ip_configuration {
      ipv4_enabled = true
      ssl_mode     = "ALLOW_UNENCRYPTED_AND_ENCRYPTED"
    }
    backup_configuration {
      enabled = false
    }
  }
}

resource "google_compute_instance" "vm" {
  name         = "vm"
  machine_type = "e2-medium"
  zone         = "us-central1-a"
  can_ip_forward = true
  network_interface {
    network = "default"
    access_config {
    }
  }
  metadata = {
    enable-oslogin     = "false"
    serial-port-enable = "true"
  }
}

resource "google_compute_instance" "vm_flags" {
  name         = "vm-flags"
  machine_type = "e2-medium"
  zone         = "us-central1-a"
  network_interface {
    network = "default"
  }
  metadata = {
    "enable-oslogin"     = "FALSE"
    "serial-port-enable" = "1"
  }
}

resource "google_compute_project_metadata" "project" {
  metadata = {
    enable-oslogin = "false"
  }
}

resource "google_compute_subnetwork" "app" {
  name          = "app"
  ip_cidr_range = "10.2.0.0/16"
  network       = "default"
}
