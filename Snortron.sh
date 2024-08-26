#!/bin/bash

# Function to install and configure Snort
install_snort() {
    echo "Installing Snort..."
    
    # Update and install dependencies
    sudo apt-get update
    sudo apt-get install -y build-essential libpcap-dev libpcre3-dev libdumbnet-dev bison flex zlib1g-dev

    # Install additional dependencies for Snort 3
    sudo apt-get install -y cmake libdnet-dev libhwloc-dev libluajit-5.1-dev libtcmalloc-minimal4 pkg-config
    
    # Download and install Snort 3
    wget https://www.snort.org/downloads/snortplus/snort-3.1.37.0.tar.gz
    tar -xzvf snort-3.1.37.0.tar.gz
    cd snort-3.1.37.0
    ./configure_cmake.sh --prefix=/usr/local --enable-tcmalloc
    cd build
    make
    sudo make install
    sudo ldconfig
    
    # Create directories for Snort configuration
    sudo mkdir -p /etc/snort/rules
    sudo mkdir /etc/snort/preproc_rules
    sudo mkdir /var/log/snort
    sudo mkdir /usr/local/lib/snort_dynamicrules
    
    # Download Snort configuration files and rules
    wget https://www.snort.org/rules/community -O community.tar.gz
    tar -xzvf community.tar.gz -C /etc/snort
    
    # Copy the configuration file
    sudo cp /etc/snort/etc/snort.conf /usr/local/etc/snort.conf
    
    # Set up logging to Elasticsearch
    configure_filebeat "snort"
    
    echo "Snort installation and configuration completed."
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
    
    # Configure Filebeat for Snort
    sudo filebeat modules enable snort
    
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

# Main script execution for Snort VM
echo "Starting automated deployment and configuration of Snort..."

# Install and configure Snort
install_snort

echo "Automated deployment and configuration of Snort completed."
