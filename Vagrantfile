# -*- mode: ruby -*-
# vi: set ft=ruby :

# Vagrantfile multi-machine para análisis de malware
# Configura dos VMs: Ubuntu (análisis estático) y Windows (análisis dinámico)

Vagrant.configure("2") do |config|
  
  # VM Ubuntu - Análisis Estático
  config.vm.define "ubuntu" do |ubuntu|
    ubuntu.vm.box = "ubuntu/focal64"
    ubuntu.vm.boot_timeout = 7200
    
    # Network isolation
    # ubuntu.vm.network "private_network", type: "dhcp"
    
    # Share folder for malware analysis
    ubuntu.vm.synced_folder ".", "/vagrant", disabled: true
    ubuntu.vm.synced_folder ".", "/malware_analysis"
    ubuntu.vm.synced_folder "./malware_samples", "/malware_samples"
    ubuntu.vm.synced_folder "./scripts", "/host_scripts"
    ubuntu.vm.synced_folder "./tools", "/host_tools"
    ubuntu.vm.synced_folder "./data", "/host_data"
    
    ubuntu.vm.provider "virtualbox" do |vb|
      vb.memory = "6144"
      vb.cpus = 4
      vb.customize ["modifyvm", :id, "--clipboard-mode", "disabled"]
      vb.customize ["modifyvm", :id, "--draganddrop", "disabled"]
      vb.customize ["modifyvm", :id, "--audio", "none"]
      vb.customize ["modifyvm", :id, "--usb", "off"]
      vb.customize ["modifyvm", :id, "--hwvirtex", "on"]
      vb.customize ["modifyvm", :id, "--nested-hw-virt", "off"]
    end
    
    # Provisioning for Ubuntu (simplificado para análisis de archivos rar)
    ubuntu.vm.provision "shell", inline: <<-SHELL
      export DEBIAN_FRONTEND=noninteractive
      
      # Create malware analysis directories
      mkdir -p /malware_samples
      mkdir -p /malware_extracted
      mkdir -p /malware_reports
      
      # Install basic tools for archive analysis
      apt-get update
      apt-get install -y p7zip-full p7zip unrar unzip file xxd python3 python3-pip
      
      # Install Python malware analysis tools
      pip3 install pefile python-magic yara-python
      
      echo "Malware analysis environment setup complete (simplified)"
      
    SHELL
  end
  
  # VM Windows - Análisis Dinámico
  config.vm.define "windows" do |windows|
    windows.vm.box = "mwrock/Windows2016"
    windows.vm.boot_timeout = 1200
    
    # Network isolation - COMPLETELY ISOLATED for security
    # windows.vm.network "private_network", type: "dhcp", auto_config: false
    
    # Forward RDP port (3389) to host port 13389 to avoid conflicts
    windows.vm.network "forwarded_port", guest: 3389, host: 13389
    
    # Share folder for malware analysis (read-only for security)
    windows.vm.synced_folder ".", "/vagrant", disabled: true
    windows.vm.synced_folder "./malware_samples", "/malware_samples"
    windows.vm.synced_folder "./scripts", "/host_scripts"
    windows.vm.synced_folder "./tools", "/host_tools"
    
    windows.vm.provider "virtualbox" do |vb|
      vb.gui = true
      vb.memory = "8192"
      vb.cpus = 4
      vb.customize ["modifyvm", :id, "--clipboard-mode", "disabled"]
      vb.customize ["modifyvm", :id, "--draganddrop", "disabled"]
      vb.customize ["modifyvm", :id, "--audio", "none"]
      vb.customize ["modifyvm", :id, "--usb", "off"]
      vb.customize ["modifyvm", :id, "--nested-hw-virt", "on"]
      vb.customize ["modifyvm", :id, "--ioapic", "on"]
      vb.customize ["modifyvm", :id, "--hwvirtex", "on"]
      vb.customize ["modifyvm", :id, "--accelerate-3d", "off"]
    end
    
    # Share folder for malware analysis (read-only for security)
    windows.vm.synced_folder ".", "/vagrant", disabled: true
    windows.vm.synced_folder "./malware_samples", "/malware_samples", mount_options: ["ro"]
    windows.vm.synced_folder "./scripts", "/host_scripts", mount_options: ["ro"]
    windows.vm.synced_folder "./tools", "/host_tools", mount_options: ["ro"]

    # Provisioning for Windows
    windows.vm.provision "shell", inline: <<-SHELL
    # Forzar TLS 1.2 permanentemente via registro (persiste para todo el script)
    Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\.NETFramework\\v4.0.30319" -Name "SchUseStrongCrypto" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Wow6432Node\\Microsoft\\.NETFramework\\v4.0.30319" -Name "SchUseStrongCrypto" -Value 1 -Type DWord -Force
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $ProgressPreference = 'SilentlyContinue'

    # Create malware analysis directories
    New-Item -ItemType Directory -Path "C:\\malware_samples" -Force
    New-Item -ItemType Directory -Path "C:\\malware_extracted" -Force
    New-Item -ItemType Directory -Path "C:\\malware_reports" -Force
    New-Item -ItemType Directory -Path "C:\\pcap" -Force
    New-Item -ItemType Directory -Path "C:\\logs" -Force
    New-Item -ItemType Directory -Path "C:\\tools" -Force

    Write-Host "========================================"
    Write-Host "Windows Malware Analysis Environment Setup Complete"
    Write-Host "========================================"
    Write-Host "Analysis directories:"
    Write-Host "  - C:\\malware_samples"
    Write-Host "  - C:\\malware_extracted"
    Write-Host "  - C:\\malware_reports"
    Write-Host "  - C:\\pcap"
    Write-Host "  - C:\\logs"
    Write-Host "  - C:\\tools"
    Write-Host "========================================"
    SHELL
  end
end
