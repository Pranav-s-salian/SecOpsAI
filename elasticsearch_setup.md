# Wazuh + Elasticsearch Setup Guide

## Option A: Docker Compose Setup (Recommended for Testing)

version: '3.7'
services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:7.17.0
    container_name: elasticsearch
    environment:
      - discovery.type=single-node
      - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
      - xpack.security.enabled=false
    ports:
      - "9200:9200"
    volumes:
      - elasticsearch_data:/usr/share/elasticsearch/data

  wazuh-manager:
    image: wazuh/wazuh-manager:4.5.0
    container_name: wazuh-manager
    ports:
      - "1514:1514/udp"
      - "1515:1515"
      - "514:514/udp"
      - "55000:55000"
    environment:
      - ELASTICSEARCH_URL=http://elasticsearch:9200
    depends_on:
      - elasticsearch
    volumes:
      - wazuh_etc:/var/ossec/etc
      - wazuh_logs:/var/ossec/logs
      - wazuh_queue:/var/ossec/queue
      - wazuh_var_multigroups:/var/ossec/var/multigroups
      - wazuh_integrations:/var/ossec/integrations
      - wazuh_active_response:/var/ossec/active-response/bin
      - wazuh_agentless:/var/ossec/agentless
      - wazuh_wodles:/var/ossec/wodles

  wazuh-dashboard:
    image: wazuh/wazuh-dashboard:4.5.0
    container_name: wazuh-dashboard
    ports:
      - "443:5601"
    environment:
      - ELASTICSEARCH_URL=http://elasticsearch:9200
      - WAZUH_API_URL=https://wazuh-manager:55000
    depends_on:
      - elasticsearch
      - wazuh-manager

volumes:
  elasticsearch_data:
  wazuh_etc:
  wazuh_logs:
  wazuh_queue:
  wazuh_var_multigroups:
  wazuh_integrations:
  wazuh_active_response:
  wazuh_agentless:
  wazuh_wodles:

## Commands to run:

# 1. Save above as docker-compose.yml
# 2. Run the stack
docker-compose up -d

# 3. Check if services are running
docker-compose ps

# 4. Check Elasticsearch
curl http://localhost:9200

# 5. Check Wazuh API
curl -k -X GET "https://localhost:55000/" -H "Content-Type: application/json"

## Option B: Manual Installation

### Install Elasticsearch:
# Download and install Elasticsearch 7.17.0
# Configure it to listen on localhost:9200

### Install Wazuh Manager:
# Follow official Wazuh installation guide
# Configure it to send data to Elasticsearch

### Install Wazuh Agent:
# Install agents on systems you want to monitor
# Configure them to send logs to Wazuh Manager