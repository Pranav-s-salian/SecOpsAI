from elasticsearch import Elasticsearch

# Connect
es = Elasticsearch(['http://localhost:9200'])

# Test 1: Ping
if es.ping():
    print(" Elasticsearch is RUNNING!")
else:
    print("Elasticsearch is NOT running")
    exit()

# Test 2: Get info
info = es.info()
print(f"\nCluster Name: {info['cluster_name']}")
print(f"Version: {info['version']['number']}")

# Test 3: Check health
health = es.cluster.health()
print(f"Status: {health['status']}")
print(f" Number of nodes: {health['number_of_nodes']}")

print("\n🎉 All tests passed! Elasticsearch is working perfectly!")