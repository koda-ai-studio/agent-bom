provider "azurerm" {
  features {}
}

resource "azurerm_storage_account" "good" {
  name                            = "corpgood"
  resource_group_name             = "rg"
  location                        = "eastus"
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  allow_nested_items_to_be_public = false
  https_traffic_only_enabled      = true
  min_tls_version                 = "TLS1_2"
  network_rules {
    default_action = "Deny"
    bypass         = ["AzureServices"]
  }
}

resource "azurerm_storage_container" "private" {
  name                  = "private"
  storage_account_name  = azurerm_storage_account.good.name
  container_access_type = "private"
}

resource "azurerm_network_security_rule" "ssh_from_office" {
  name                        = "ssh"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22"
  source_address_prefix       = "203.0.113.0/24"
  destination_address_prefix  = "*"
  resource_group_name         = "rg"
  network_security_group_name = "nsg"
}

resource "azurerm_network_security_rule" "deny_any" {
  name                        = "deny"
  priority                    = 4000
  direction                   = "Inbound"
  access                      = "Deny"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = "rg"
  network_security_group_name = "nsg"
}

resource "azurerm_network_security_rule" "outbound_any" {
  name                        = "egress"
  priority                    = 200
  direction                   = "Outbound"
  access                      = "Allow"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = "rg"
  network_security_group_name = "nsg"
}

resource "azurerm_network_security_group" "inline_web" {
  name                = "nsg-web"
  location            = "eastus"
  resource_group_name = "rg"

  security_rule {
    name                       = "https"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "Internet"
    destination_address_prefix = "*"
  }
}

resource "azurerm_postgresql_server" "db" {
  name                             = "db"
  administrator_login_password     = var.db_password
  ssl_enforcement_enabled          = true
  ssl_minimal_tls_version_enforced = "TLS1_2"
  public_network_access_enabled    = false
}

resource "azurerm_mssql_server" "sql" {
  name                          = "sql"
  minimum_tls_version           = "1.2"
  public_network_access_enabled = false
}

resource "azurerm_mssql_server_extended_auditing_policy" "sql" {
  server_id = azurerm_mssql_server.sql.id
}

resource "azurerm_postgresql_flexible_server" "flex" {
  name                = "flex"
  delegated_subnet_id = "subnet"
  private_dns_zone_id = "zone"
}

resource "azurerm_mssql_database" "data" {
  name      = "data"
  server_id = azurerm_mssql_server.sql.id
}

resource "azurerm_key_vault" "kv" {
  name                       = "kv"
  tenant_id                  = "00000000-0000-0000-0000-000000000000"
  sku_name                   = "standard"
  purge_protection_enabled   = true
  soft_delete_retention_days = 90
}

resource "azurerm_managed_disk" "data" {
  name                   = "data"
  storage_account_type   = "Premium_LRS"
  create_option          = "Empty"
  disk_size_gb           = 100
  disk_encryption_set_id = azurerm_disk_encryption_set.cmk.id
}

resource "azurerm_network_interface" "vm" {
  name = "vm-nic"
  ip_configuration {
    name                          = "primary"
    subnet_id                     = "subnet"
    private_ip_address_allocation = "Dynamic"
  }
}

resource "azurerm_network_watcher_flow_log" "nsg" {
  name                 = "flow"
  network_watcher_name = "nw"
  resource_group_name  = "rg"
  enabled              = true
  retention_policy {
    enabled = true
    days    = 90
  }
}
