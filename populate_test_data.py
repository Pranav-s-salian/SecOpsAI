#!/usr/bin/env python3
"""
Script to populate Elasticsearch with sample Wazuh alert data for testing
"""

import json
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch

def create_sample_auth_events():
    """Create sample authentication events"""
    events = []
    base_time = datetime.now()
    
    # Failed SSH attempts
    for i in range(10):
        event = {
            "@timestamp": (base_time - timedelta(hours=i, minutes=i*5)).isoformat(),
            "agent": {
                "id": "001",
                "name": "web-server-01",
                "ip": "192.168.1.100"
            },
            "rule": {
                "level": 5,
                "id": "5716",
                "description": "SSH authentication failed",
                "groups": ["authentication_failed", "sshd"]
            },
            "data": {
                "srcip": f"192.168.1.{50 + i}",
                "srcuser": "admin" if i < 5 else "root",
                "srcport": "22",
                "status": "failed"
            },
            "location": "/var/log/auth.log",
            "full_log": f"Failed password for admin from 192.168.1.{50 + i} port 22 ssh2"
        }
        events.append(event)
    
    # Successful SSH logins
    for i in range(5):
        event = {
            "@timestamp": (base_time - timedelta(hours=i*2)).isoformat(),
            "agent": {
                "id": "001", 
                "name": "web-server-01",
                "ip": "192.168.1.100"
            },
            "rule": {
                "level": 3,
                "id": "5715",
                "description": "SSH authentication success",
                "groups": ["authentication_success", "sshd"]
            },
            "data": {
                "srcip": f"192.168.1.{10 + i}",
                "srcuser": "admin",
                "srcport": "22", 
                "status": "success"
            },
            "location": "/var/log/auth.log",
            "full_log": f"Accepted password for admin from 192.168.1.{10 + i} port 22 ssh2"
        }
        events.append(event)
    
    # Brute force attack
    attacker_ip = "192.168.1.99"
    for i in range(20):
        event = {
            "@timestamp": (base_time - timedelta(minutes=i*2)).isoformat(),
            "agent": {
                "id": "002",
                "name": "db-server-01", 
                "ip": "192.168.1.101"
            },
            "rule": {
                "level": 10,
                "id": "5732",
                "description": "SSH brute force attack",
                "groups": ["authentication_attacks", "sshd"]
            },
            "data": {
                "srcip": attacker_ip,
                "srcuser": "root",
                "srcport": "22",
                "status": "failed"
            },
            "location": "/var/log/auth.log",
            "full_log": f"Failed password for root from {attacker_ip} port 22 ssh2"
        }
        events.append(event)
    
    return events

def create_sample_security_alerts():
    """Create sample high-priority security alerts"""
    alerts = []
    base_time = datetime.now()
    
    # Web attack alerts
    for i in range(5):
        alert = {
            "@timestamp": (base_time - timedelta(hours=i)).isoformat(),
            "agent": {
                "id": "001",
                "name": "web-server-01",
                "ip": "192.168.1.100"
            },
            "rule": {
                "level": 12,
                "id": "40501", 
                "description": "SQL injection attempt detected",
                "groups": ["web", "attacks", "sql_injection"]
            },
            "data": {
                "srcip": f"10.0.0.{100 + i}",
                "url": "/admin/login.php",
                "method": "POST"
            },
            "location": "/var/log/apache2/access.log",
            "full_log": f"10.0.0.{100 + i} - - POST /admin/login.php?id=1' OR '1'='1"
        }
        alerts.append(alert)
    
    # Malware detection
    for i in range(3):
        alert = {
            "@timestamp": (base_time - timedelta(hours=i*3)).isoformat(),
            "agent": {
                "id": "003",
                "name": "workstation-05",
                "ip": "192.168.1.205"
            },
            "rule": {
                "level": 15,
                "id": "31100",
                "description": "Malware detected by ClamAV",
                "groups": ["malware", "antivirus"]
            },
            "data": {
                "filename": f"/tmp/suspicious_file_{i}.exe",
                "virus_name": "Trojan.Generic.KDV.123456"
            },
            "location": "/var/log/clamav/clamav.log",
            "full_log": f"FOUND Trojan.Generic.KDV.123456 in /tmp/suspicious_file_{i}.exe"
        }
        alerts.append(alert)
    
    return alerts

def populate_elasticsearch():
    """Populate Elasticsearch with test data"""
    try:
        # Connect to Elasticsearch
        es = Elasticsearch(['http://localhost:9200'])
        
        if not es.ping():
            print("❌ Cannot connect to Elasticsearch")
            return False
        
        print("✅ Connected to Elasticsearch")
        
        # Create index template for Wazuh alerts
        index_template = {
            "index_patterns": ["wazuh-alerts-*"],
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0
            },
            "mappings": {
                "properties": {
                    "@timestamp": {"type": "date"},
                    "agent.id": {"type": "keyword"},
                    "agent.name": {"type": "keyword"},
                    "rule.level": {"type": "integer"},
                    "rule.id": {"type": "keyword"},
                    "rule.description": {"type": "text"},
                    "rule.groups": {"type": "keyword"},
                    "data.srcip": {"type": "ip"},
                    "data.srcuser": {"type": "keyword"}
                }
            }
        }
        
        # Create template
        try:
            es.indices.put_template(name="wazuh-alerts", body=index_template)
            print("Created Wazuh alerts index template")
        except Exception as e:
            print(f"⚠️ Template creation warning: {e}")
        
        # Generate index name
        today = datetime.now().strftime("%Y.%m.%d")
        index_name = f"wazuh-alerts-{today}"
        
        # Create authentication events
        auth_events = create_sample_auth_events()
        print(f"Created {len(auth_events)} authentication events")
        
        # Create security alerts  
        security_alerts = create_sample_security_alerts()
        print(f"Created {len(security_alerts)} security alerts")
        
        # Combine all events
        all_events = auth_events + security_alerts
        
        # Bulk index the documents
        bulk_body = []
        for event in all_events:
            bulk_body.append({"index": {"_index": index_name}})
            bulk_body.append(event)
        
        # Execute bulk indexing
        response = es.bulk(body=bulk_body, refresh=True)
        
        if response.get("errors"):
            print("❌ Some errors occurred during bulk indexing")
            for item in response["items"]:
                if "error" in item.get("index", {}):
                    print(f"   Error: {item['index']['error']}")
        else:
            print(f"Successfully indexed {len(all_events)} events to {index_name}")
        
        # Verify data
        count_response = es.count(index=index_name)
        total_docs = count_response["count"]
        print(f"Total documents in index: {total_docs}")
        
        # Show sample search
        search_response = es.search(
            index=index_name,
            body={
                "query": {"match": {"rule.groups": "authentication_failed"}},
                "size": 3
            }
        )
        
        failed_auth_count = search_response["hits"]["total"]["value"]
        print(f" Failed authentication events: {failed_auth_count}")
        
        return True
        
    except Exception as e:
        print(f" Error populating Elasticsearch: {e}")
        return False

if __name__ == "__main__":
    print(" Populating Elasticsearch with sample Wazuh data...")
    print("=" * 60)
    
    success = populate_elasticsearch()
    
    if success:
        
        print(" Sample data population complete")
    else:
        print("\n Failed to populate sample data")