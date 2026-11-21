terraform {
  required_version = ">= 1.6"
  required_providers {
    google = { source = "hashicorp/google", version = "~> 6.10" }
    random = { source = "hashicorp/random", version = "~> 3.6" }
  }
}

variable "project_id" {
  type = string
}

variable "region" {
  type    = string
  default = "us-central1"
}

variable "image" {
  description = "The shared lab image, pinned by digest: docker.io/<org>/<repo>@sha256:<digest>. Cloud Run pulls Docker Hub images directly."
  type        = string
}

provider "google" {
  project = var.project_id
  region  = var.region
}

resource "random_id" "suffix" {
  byte_length = 3
}

locals {
  name   = "abom-lab-${random_id.suffix.hex}"
  labels = { purpose = "agent-bom-lab", ttl = "destroy-same-day" }
}

resource "google_project_service" "run" {
  service            = "run.googleapis.com"
  disable_on_destroy = false
}

# Planted: "training data" bucket readable by anyone. An organization policy
# that enforces public access prevention will refuse this binding; the lab
# still works, and the scan then shows the bucket as private.
resource "google_storage_bucket" "training" {
  name                        = "${local.name}-training-data"
  location                    = "US"
  uniform_bucket_level_access = true
  force_destroy               = true
  labels                      = local.labels
}

resource "google_storage_bucket_iam_member" "public_read" {
  bucket = google_storage_bucket.training.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}

resource "google_service_account" "agent" {
  account_id   = "${local.name}-agent"
  display_name = "agent-bom lab agent"
}

# Planted: the agent's service account administers every bucket in the project.
resource "google_project_iam_member" "agent_storage_admin" {
  project = var.project_id
  role    = "roles/storage.admin"
  member  = "serviceAccount:${google_service_account.agent.email}"
}

resource "google_cloud_run_v2_service" "agent" {
  name                = "agent"
  location            = var.region
  deletion_protection = false
  labels              = local.labels
  depends_on          = [google_project_service.run]

  template {
    service_account = google_service_account.agent.email
    scaling {
      min_instance_count = 0
      max_instance_count = 1
    }
    containers {
      image = var.image
      resources {
        limits = { cpu = "1", memory = "512Mi" }
      }
      # Planted: a model key in plain environment configuration (placeholder value).
      env {
        name  = "OPENAI_API_KEY"
        value = "lab-placeholder-not-a-real-key"
      }
      env {
        name  = "TRAINING_BUCKET"
        value = google_storage_bucket.training.name
      }
    }
  }
}

output "service" {
  value = google_cloud_run_v2_service.agent.name
}

output "training_bucket" {
  value = google_storage_bucket.training.name
}
