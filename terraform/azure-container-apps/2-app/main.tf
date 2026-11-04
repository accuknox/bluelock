terraform {
  required_version = ">= 1.8.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }
}

provider "azurerm" {
  features {}
}

data "azurerm_resource_group" "this" {
  name = var.resource_group_name
}

data "azurerm_container_app_environment" "this" {
  name                = var.container_app_environment
  resource_group_name = var.resource_group_name
}

resource "azurerm_container_app" "this" {
  name                         = var.container_app_name
  resource_group_name          = data.azurerm_resource_group.this.name
  container_app_environment_id = data.azurerm_container_app_environment.this.id

  revision_mode = "Single"

  template {
    min_replicas = 2
    max_replicas = 2

    cooldown_period_in_seconds  = 300
    polling_interval_in_seconds = 30

    # ---------------------------------------------------------
    # Main container: armored-container
    # ---------------------------------------------------------

    container {
      name   = "armored-container"
      image  = "public.ecr.aws/k9v9d5v2/accuknox-bluelock/ka-socat-demo:latest"
      cpu    = 0.5
      memory = "1Gi"

      command = [
        "/kubearmor/bluelock",
        "socat",
        "TCP-LISTEN:1337,reuseaddr,fork",
        "EXEC:bash,pty,stderr,setsid,sigint,sane"
      ]

      env {
        name  = "CONTAINERNAME"
        value = "armored-container"
      }

      env {
        name  = "CONTAINERIMAGE"
        value = "public.ecr.aws/k9v9d5v2/accuknox-bluelock/ka-socat-demo:latest"
      }

      env {
        name  = "K8S"
        value = "false"
      }

      volume_mounts {
        name = "kubearmor-dir"
        path = "/kubearmor"
      }
    }

    # ---------------------------------------------------------
    # Sidedcar container: kubearmor-vm-adapter
    # ---------------------------------------------------------

    container {
      name   = "kubearmor-vm-adapter"
      image  = "docker.io/accuknox/vm-adapter:v0.1.29"
      cpu    = 0.5
      memory = "1Gi"

      args = [
        "--kubearmor-addr=localhost:32767",
        "--relay-server-addr=${var.vm_public_ip}:32768",
        "--node-state-refresh=4",
        "--policy-list-enable=true",
        "--policy-list-relay-frequency=5m0s",
        "--sia-addr=${var.vm_public_ip}:32769",
        "--pea-addr=${var.vm_public_ip}:32770",
        "--harden-addr=${var.vm_public_ip}:32771",
        "--annotation-topic=annotation",
        "--annotation-enable=true"
      ]

      env {
        name  = "test"
        value = "true"
      }

      volume_mounts {
        name = "opt-storage"
        path = "/opt"
      }
    }

    # ---------------------------------------------------------
    # Init container: bluelock
    # ---------------------------------------------------------

    init_container {
      name   = "bluelock"
      image  = "public.ecr.aws/k9v9d5v2/accuknox-bluelock:v1.0.0"
      cpu    = 0.25
      memory = "0.5Gi"

      volume_mounts {
        name = "kubearmor-dir"
        path = "/kubearmor"
      }
    }

    # ---------------------------------------------------------
    # Volumes
    # ---------------------------------------------------------

    volume {
      name         = "kubearmor-dir"
      storage_type = "EmptyDir"
    }

    volume {
      name         = "opt-storage"
      storage_type = "EmptyDir"
    }
  }

  # -----------------------------------------------------------
  # TCP ingress
  # -----------------------------------------------------------

  ingress {
    external_enabled = true
    exposed_port     = 1337
    target_port      = 1337
    transport        = "tcp"

    traffic_weight {
      percentage      = 100
      latest_revision = true
    }
  }
}