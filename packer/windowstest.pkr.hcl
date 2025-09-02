packer {
    required_plugins {
    azure = {
      source  = "github.com/hashicorp/azure"
      version = "~> 2.4.0"
    }
  }
}

source "azure-arm" "windows_2022" {
  #build_resource_group_name          = "rg-bicep-test"
  virtual_network_name              = "vnet-northeurope"
  virtual_network_subnet_name       = "snet-northeurope-1"
  virtual_network_resource_group_name = "rg-homelab-north"
  
  #managed_image_name            = "myManagedImage"
  location                     = "northeurope"
  vm_size                      = "Standard_D2s_v3"
  os_type                      = "Windows"
  image_publisher              = "MicrosoftWindowsServer"
  image_offer                  = "WindowsServer"
  image_sku                    = "2022-Datacenter-g2"
  image_version                = "latest"
  security_type               = "TrustedLaunch"
  secure_boot_enabled         = true
  vtpm_enabled                = true
  communicator                 = "winrm"
  winrm_username               = "packer"
  winrm_password               = "Admin#123"
  winrm_insecure               = true
  winrm_timeout                     = "5m"
  winrm_use_ssl                     = true
  azure_tags = {
    created_by = "packer"
  }
  shared_image_gallery_destination {
    subscription = "db7ae7e3-3ce9-4854-9c79-6b022bfa2fc3"
    gallery_name   = "CitrixImages"
    image_name           = "packertest"
    image_version        = "1.0.1"  # Version des Images in SIG
    resource_group = "rg-homelab"
  }
  # Optional: Netzwerk oder weitere Einstellungen
}

build {
  sources = ["source.azure-arm.windows_2022"]

  provisioner "powershell" {
    script = "./prep.ps1"
  }

  provisioner "file" {
    source      = "./info.txt"
    destination = "C:/mytemp/info.txt"
  }

  provisioner "shell" {
    inline = [
      "$env:SystemRoot\\System32\\Sysprep\\Sysprep.exe /oobe /generalize /quiet /quit"
    ]
  }
}