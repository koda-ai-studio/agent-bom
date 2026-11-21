resource "aws_ecs_task_definition" "agent" {
  container_definitions = jsonencode([{
    environment = [{ name = "OPENAI_API_KEY", value = "placeholder" }]
    secrets = [{ name = "ANTHROPIC_API_KEY", valueFrom = "fixture-reference" }]
  }])
}
resource "azurerm_container_app" "agent" {
  template {
    container {
      env {
        name = "ANTHROPIC_API_KEY"
        value = "placeholder"
      }
      env {
        name = "OPENAI_API_KEY"
        secret_name = "model-key"
      }
    }
  }
}
resource "google_cloud_run_v2_service" "agent" {
  template {
    containers {
      env {
        name = "GEMINI_API_KEY"
        value = "placeholder"
      }
      env {
        name = "ANTHROPIC_API_KEY"
        value_source {
          secret_key_ref {
            secret = "model-key"
            version = "latest"
          }
        }
      }
    }
  }
}
resource "google_project_iam_member" "admin" {
  role = "roles/storage.admin"
}
resource "google_project_iam_binding" "viewer" {
  role = "roles/storage.objectViewer"
}
resource "azurerm_role_assignment" "broad" {
  scope = azurerm_resource_group.lab.id
  role_definition_name = "Contributor"
}
resource "azurerm_role_assignment" "scoped" {
  scope = azurerm_storage_account.training.id
  role_definition_name = "Storage Blob Data Contributor"
}
resource "azurerm_storage_account" "training" {
  allow_nested_items_to_be_public = true
}
resource "azurerm_storage_container" "training" {
  storage_account_id = azurerm_storage_account.training.id
  container_access_type = "blob"
}
resource "aws_s3_bucket" "default_encryption" {
  bucket = "fixture-default-encryption"
}
