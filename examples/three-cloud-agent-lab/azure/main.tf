terraform {
  required_version = ">= 1.6"
  required_providers {
    azurerm = { source = "hashicorp/azurerm", version = "~> 4.10" }
    random  = { source = "hashicorp/random", version = "~> 3.6" }
  }
}

variable "subscription_id" {
  type = string
}

variable "location" {
  type    = string
  default = "eastus"
}

variable "image" {
  description = "The shared lab image, pinned by digest: docker.io/<org>/<repo>@sha256:<digest>."
  type        = string
}

provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
}

resource "random_id" "suffix" {
  byte_length = 3
}

locals {
  name = "abom-lab-${random_id.suffix.hex}"
  tags = { purpose = "agent-bom-lab", ttl = "destroy-same-day" }
}

resource "azurerm_resource_group" "lab" {
  name     = local.name
  location = var.location
  tags     = local.tags
}

# Planted: "training data" container readable by anyone.
resource "azurerm_storage_account" "training" {
  name                            = "abomlab${random_id.suffix.hex}"
  resource_group_name             = azurerm_resource_group.lab.name
  location                        = azurerm_resource_group.lab.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  allow_nested_items_to_be_public = true
  tags                            = local.tags
}

resource "azurerm_storage_container" "training" {
  name                  = "training-data"
  storage_account_id    = azurerm_storage_account.training.id
  container_access_type = "blob"
}

resource "azurerm_container_app_environment" "lab" {
  name                = local.name
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location
  tags                = local.tags
}

resource "azurerm_container_app" "agent" {
  name                         = "agent"
  resource_group_name          = azurerm_resource_group.lab.name
  container_app_environment_id = azurerm_container_app_environment.lab.id
  revision_mode                = "Single"
  tags                         = local.tags

  identity {
    type = "SystemAssigned"
  }

  template {
    min_replicas = 1
    max_replicas = 1
    container {
      name   = "agent"
      image  = var.image
      cpu    = 0.25
      memory = "0.5Gi"
      # Planted: a model key in plain environment configuration (placeholder value).
      env {
        name  = "OPENAI_API_KEY"
        value = "lab-placeholder-not-a-real-key"
      }
      env {
        name  = "TRAINING_ACCOUNT"
        value = azurerm_storage_account.training.name
      }
    }
  }
}

# Planted: the agent's identity can change anything in the resource group.
resource "azurerm_role_assignment" "agent_contributor" {
  scope                = azurerm_resource_group.lab.id
  role_definition_name = "Contributor"
  principal_id         = azurerm_container_app.agent.identity[0].principal_id
}

resource "azurerm_role_assignment" "agent_blob" {
  scope                = azurerm_storage_account.training.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_container_app.agent.identity[0].principal_id
}

output "resource_group" {
  value = azurerm_resource_group.lab.name
}

output "training_account" {
  value = azurerm_storage_account.training.name
}
