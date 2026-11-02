provider "azurerm" {
  features {}
}

resource "azurerm_storage_account" "logs" {
  name                      = "corplogs"
  resource_group_name       = "rg"
  location                  = "eastus"
  account_tier              = "Standard"
  account_replication_type  = "LRS"
  allow_blob_public_access  = true
  enable_https_traffic_only = false
  min_tls_version           = "TLS1_0"
  network_rules {
    default_action = "Allow"
  }
}

resource "azurerm_storage_account" "v4names" {
  name                            = "corpv4"
  allow_nested_items_to_be_public = true
  https_traffic_only_enabled      = false
  min_tls_version                 = "TLS1_1"
}

resource "azurerm_storage_container" "public" {
  name                  = "public"
  storage_account_name  = azurerm_storage_account.logs.name
  container_access_type = "blob"
}

resource "azurerm_network_security_rule" "ssh" {
  name                        = "ssh"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = "rg"
  network_security_group_name = "nsg"
}

resource "azurerm_network_security_group" "inline" {
  name                = "nsg"
  location            = "eastus"
  resource_group_name = "rg"

  security_rule {
    name                       = "rdp"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_ranges    = ["3389", "8080"]
    source_address_prefixes    = ["Internet"]
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "any"
    priority                   = 120
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "0.0.0.0/0"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "web"
    priority                   = 130
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "8443"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

resource "azurerm_postgresql_server" "db" {
  name                          = "db"
  administrator_login_password  = "NotARealPassw0rd-demo"
  ssl_enforcement_enabled       = false
  public_network_access_enabled = true
}

resource "azurerm_mysql_server" "legacy" {
  name                             = "mysql"
  ssl_enforcement_enabled          = true
  ssl_minimal_tls_version_enforced = "TLS1_0"
}

resource "azurerm_mssql_server" "sql" {
  name                          = "sql"
  public_network_access_enabled = true
}

resource "azurerm_mssql_server" "sql_default_public" {
  name = "sql-default"
}

resource "azurerm_postgresql_flexible_server" "flex" {
  name                          = "flex"
  public_network_access_enabled = true
}

resource "azurerm_mssql_database" "data" {
  name                                = "data"
  server_id                           = azurerm_mssql_server.sql.id
  transparent_data_encryption_enabled = false
}

resource "azurerm_key_vault" "kv" {
  name                     = "kv"
  tenant_id                = "00000000-0000-0000-0000-000000000000"
  sku_name                 = "standard"
  purge_protection_enabled = false
}

resource "azurerm_key_vault" "kv_default" {
  name      = "kv2"
  tenant_id = "00000000-0000-0000-0000-000000000000"
  sku_name  = "standard"
}

resource "azurerm_managed_disk" "data" {
  name                 = "data"
  storage_account_type = "Standard_LRS"
  create_option        = "Empty"
  disk_size_gb         = 100
}

resource "azurerm_network_interface" "vm" {
  name = "vm-nic"
  ip_configuration {
    name                          = "primary"
    subnet_id                     = "subnet"
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.vm.id
  }
}

resource "azurerm_network_watcher_flow_log" "nsg" {
  name                 = "flow"
  network_watcher_name = "nw"
  resource_group_name  = "rg"
  enabled              = false
  retention_policy {
    enabled = true
    days    = 7
  }
}

resource "azurerm_network_watcher_flow_log" "short" {
  name                 = "flow-short"
  network_watcher_name = "nw"
  resource_group_name  = "rg"
  enabled              = true
  retention_policy {
    enabled = false
    days    = 0
  }
}
