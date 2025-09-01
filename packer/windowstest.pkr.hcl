packer {
    required_plugins {
    azure = {
      source  = "github.com/hashicorp/azure"
      version = "~> 2"
    }
  }
}

source "azure-arm" "windows_2022" {
  
  managed_image_resource_group_name = "rg-bicep-test"
  managed_image_name            = "myManagedImage"
  location                     = "northeurope"
  vm_size                      = "Standard_D2s_v3"
  os_type                      = "Windows"
  image_publisher              = "MicrosoftWindowsServer"
  image_offer                  = "WindowsServer"
  image_sku                    = "2022-Datacenter"
  image_version                = "latest"
  communicator                 = "winrm"
  winrm_username               = "packer"
  winrm_password               = "Admin#123"
  azure_tags = {
    created_by = "packer"
  }
  
  shared_image_gallery_name   = "CitrixImages"
  shared_image_name           = "packertest"
  shared_image_version        = "1.0.0"  # Version des Images in SIG

  # Optional: Netzwerk oder weitere Einstellungen
}

build {
  sources = ["source.azure-arm.windows_2022"]
}