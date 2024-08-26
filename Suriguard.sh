#!/bin/bash

# Function to install and configure Suricata
install_suricata() {
    echo "Installing Suricata..."
    
    # Update and install dependencies
    sudo apt-get update
    sudo apt-get install -y software-properties-common
    sudo add-apt-repository -y ppa:oisf/suricata-stable
    sudo apt-get update
    sudo apt-get install -y suricata
    
    # Enable Suricata service
    sudo systemctl enable suricata
    sudo systemctl start suricata
    
    # Set up logging to Elasticsearch
    configure_filebeat "suricata"
    
    echo "Suricata installation and configuration completed."
}

# Function to configure Filebeat to send logs to Elasticsearch
configure_filebeat() {
    IDS_NAME=$1
    echo "Configuring Filebeat for $IDS_NAME..."
    
    # Prompt for Elasticsearch details
    read -p "Enter the Elasticsearch IP: " es_ip
    read -p "Enter the Elasticsearch username: " es_username
    read -sp "Enter the Elasticsearch password: " es_password
    echo
    
    # Install Filebeat
    wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
    sudo apt-get install apt-transport-https
    echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-7.x.list
    sudo apt-get update
    sudo apt-get install filebeat
    
    # Configure Filebeat for Suricata
    sudo filebeat modules enable suricata
    
    # Configure Filebeat to send logs to the central Elasticsearch server
    echo "output.elasticsearch:
  hosts: [\"$es_ip:9200\"]
  username: \"$es_username\"
  password: \"$es_password\"" | sudo tee -a /etc/filebeat/filebeat.yml
    
    # Start and enable Filebeat
    sudo filebeat setup
    sudo systemctl start filebeat
    sudo systemctl enable filebeat
    
    echo "Filebeat configuration for $IDS_NAME completed."
}

# Main script execution for Suricata VM
echo "Starting automated deployment and configuration of Suricata..."

# Install and configure Suricata
install_suricata

echo "Automated deployment and configuration of Suricata completed."
