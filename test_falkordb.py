from falkordb import FalkorDB

# Connect Python to the local FalkorDB server

db = FalkorDB(host="localhost", port=6379)

# Create or open a graph named CyberGraph

graph = db.select_graph("CyberGraph")

# Create a sample cybersecurity alert and device

result = graph.query("""
CREATE (a:Alert {id: 'ALT-001', severity: 'high'})
CREATE (d:Device {id: 'DEV-001', hostname: 'dev-laptop-01'})
CREATE (a)-[:AFFECTS]->(d)
RETURN a.id AS alert_id, a.severity AS severity,
d.id AS device_id, d.hostname AS hostname
""")

# Display the result

for record in result.result_set:
 print("Alert ID:", record[0])
 print("Severity:", record[1])
 print("Device ID:", record[2])
 print("Hostname:", record[3])

print("\nCyberGraph database connection successful!")
