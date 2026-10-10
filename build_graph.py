from falkordb import FalkorDB

# Connect to FalkorDB
db = FalkorDB(host="localhost", port=6379)

# Select our graph
graph = db.select_graph("CyberGraph")

# Create a sample cybersecurity investigation graph
graph.query("""
MERGE (a:Alert {id: 'ALT-002'})
SET a.severity = 'critical',
    a.description = 'Suspicious activity detected'

MERGE (d:Device {id: 'DEV-002'})
SET d.hostname = 'finance-server'

MERGE (v:Vulnerability {id: 'VUL-001'})
SET v.name = 'Unpatched software',
    v.severity = 'high'

MERGE (i:Identity {id: 'ID-001'})
SET i.username = 'finance_user'

MERGE (asset:Asset {id: 'AST-001'})
SET asset.name = 'Financial Database',
    asset.criticality = 'critical'

MERGE (a)-[:AFFECTS]->(d)
MERGE (d)-[:HAS_VULNERABILITY]->(v)
MERGE (i)-[:ACCESSES]->(d)
MERGE (d)-[:CONNECTS_TO]->(asset)
""")

print("Cybersecurity graph created successfully!")

# Display the connected investigation graph
result = graph.query("""
MATCH (a:Alert)-[:AFFECTS]->(d:Device)
OPTIONAL MATCH (d)-[:HAS_VULNERABILITY]->(v:Vulnerability)
OPTIONAL MATCH (i:Identity)-[:ACCESSES]->(d)
OPTIONAL MATCH (d)-[:CONNECTS_TO]->(asset:Asset)
RETURN a.id, a.severity,
       d.hostname, v.name,
       i.username, asset.name
""")

for row in result.result_set:
    print("\n--- Investigation Graph ---")
    print("Alert:", row[0])
    print("Severity:", row[1])
    print("Device:", row[2])
    print("Vulnerability:", row[3])
    print("Identity:", row[4])
    print("Connected Asset:", row[5])