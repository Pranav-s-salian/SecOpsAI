#!/usr/bin/env python3
"""
Script to clear Elasticsearch database - removes all Wazuh alert indices
"""

from elasticsearch import Elasticsearch
import sys

def clear_elasticsearch_database():
    """Clear all Wazuh-related indices from Elasticsearch"""
    try:
        # Connect to Elasticsearch
        es = Elasticsearch(['http://localhost:9200'])
        
        if not es.ping():
            print("❌ Cannot connect to Elasticsearch at localhost:9200")
            return False
        
        print("✅ Connected to Elasticsearch")
        info = es.info()
        print(f"📊 Cluster: {info['cluster_name']}, Version: {info['version']['number']}")
        print()
        
        # Get all indices
        all_indices = es.indices.get_alias(index="*")
        
        # Filter Wazuh-related indices
        wazuh_patterns = ["wazuh-alerts-*", "wazuh-archives-*", "filebeat-*"]
        indices_to_delete = []
        
        for index_name in all_indices.keys():
            if any(pattern.replace("*", "") in index_name for pattern in wazuh_patterns):
                indices_to_delete.append(index_name)
        
        if not indices_to_delete:
            print("ℹ️  No Wazuh indices found to delete")
            return True
        
        print(f"🔍 Found {len(indices_to_delete)} Wazuh indices:")
        for idx in indices_to_delete:
            # Get document count
            try:
                count = es.count(index=idx)["count"]
                print(f"   • {idx} ({count} documents)")
            except:
                print(f"   • {idx}")
        
        print()
        confirmation = input("⚠️  Are you sure you want to DELETE all these indices? (yes/no): ").strip().lower()
        
        if confirmation != 'yes':
            print("❌ Operation cancelled")
            return False
        
        print()
        print("🗑️  Deleting indices...")
        
        deleted_count = 0
        for index_name in indices_to_delete:
            try:
                es.indices.delete(index=index_name)
                print(f"   ✅ Deleted: {index_name}")
                deleted_count += 1
            except Exception as e:
                print(f"   ❌ Failed to delete {index_name}: {e}")
        
        print()
        print(f"✅ Successfully deleted {deleted_count}/{len(indices_to_delete)} indices")
        print("🎉 Database cleared!")
        
        return True
        
    except Exception as e:
        print(f"❌ Error clearing database: {e}")
        import traceback
        traceback.print_exc()
        return False

def clear_all_elasticsearch_data():
    """Nuclear option - delete ALL indices (use with caution!)"""
    try:
        es = Elasticsearch(['http://localhost:9200'])
        
        if not es.ping():
            print("❌ Cannot connect to Elasticsearch")
            return False
        
        print("⚠️  WARNING: This will delete ALL indices in Elasticsearch!")
        print("🚨 This includes system indices and all data!")
        print()
        
        all_indices = list(es.indices.get_alias(index="*").keys())
        print(f"📊 Total indices found: {len(all_indices)}")
        
        confirmation = input("⚠️  Type 'DELETE EVERYTHING' to confirm: ").strip()
        
        if confirmation != 'DELETE EVERYTHING':
            print("❌ Operation cancelled")
            return False
        
        print()
        print("🗑️  Deleting ALL indices...")
        
        for index_name in all_indices:
            try:
                if not index_name.startswith('.'):  # Skip system indices
                    es.indices.delete(index=index_name)
                    print(f"   ✅ Deleted: {index_name}")
            except Exception as e:
                print(f"   ❌ Failed to delete {index_name}: {e}")
        
        print()
        print("✅ All non-system indices deleted!")
        
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

if __name__ == "__main__":
    print("🗑️  ELASTICSEARCH DATABASE CLEANER")
    print("=" * 60)
    print()
    print("Choose an option:")
    print("1. Clear Wazuh indices only (recommended)")
    print("2. Clear ALL indices (nuclear option - use with caution!)")
    print("3. Cancel")
    print()
    
    choice = input("Enter your choice (1/2/3): ").strip()
    
    if choice == "1":
        print()
        print("🎯 Clearing Wazuh indices...")
        print("=" * 60)
        clear_elasticsearch_database()
    elif choice == "2":
        print()
        print("💣 Nuclear option selected...")
        print("=" * 60)
        clear_all_elasticsearch_data()
    else:
        print("❌ Operation cancelled")
    
    print()
    print("=" * 60)
    print("✨ Done!")
