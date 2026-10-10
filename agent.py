from falkordb import FalkorDB


# Connect the agent to FalkorDB
db = FalkorDB(host="localhost", port=6379)
graph = db.select_graph("CyberGraph")


def investigate_alert(alert_id: str) -> dict:
    """
    Investigate a cybersecurity alert using connected graph data.
    This function reads graph data and recommends actions.
    It does not execute security actions.
    """

    # 1. Find the alert and its connected entities
    result = graph.query(
        """
        MATCH (a:Alert {id: $alert_id})
        OPTIONAL MATCH (a)-[:AFFECTS]->(d:Device)
        OPTIONAL MATCH (d)-[:HAS_VULNERABILITY]->(v:Vulnerability)
        OPTIONAL MATCH (i:Identity)-[:ACCESSES]->(d)
        OPTIONAL MATCH (d)-[:CONNECTS_TO]->(asset:Asset)
        RETURN a.id AS alert_id,
               a.severity AS severity,
               a.description AS description,
               d.hostname AS device,
               v.name AS vulnerability,
               v.severity AS vulnerability_severity,
               i.username AS identity,
               asset.name AS asset,
               asset.criticality AS asset_criticality
        """,
        {"alert_id": alert_id}
    )

    # 2. Handle alerts that do not exist
    if not result.result_set:
        return {
            "status": "not_found",
            "alert_id": alert_id,
            "message": "No matching alert was found in FalkorDB."
        }

    investigations = []

    # 3. Analyze each returned graph record
    for row in result.result_set:
        severity = row[1] or "unknown"
        device = row[3]
        vulnerability = row[4]
        vulnerability_severity = row[5]
        identity = row[6]
        asset = row[7]
        asset_criticality = row[8]

        # 4. Create transparent investigation findings
        findings = []

        if severity.lower() == "critical":
            findings.append(
                "The alert is labelled critical in the graph."
            )

        if vulnerability:
            findings.append(
                f"The connected device has a recorded vulnerability: "
                f"{vulnerability}."
            )

        if identity:
            findings.append(
                f"The graph links identity {identity} to the device."
            )

        if asset:
            findings.append(
                f"The device is connected to asset {asset}."
            )

        if not findings:
            findings.append(
                "There is insufficient connected information "
                "to explain this alert in detail."
            )

        # 5. Recommend investigation steps
        recommendations = [
            "Review the original alert and validate its source.",
            "Verify the affected device and gather relevant logs.",
            "Confirm graph relationships against trusted security evidence."
        ]

        if vulnerability:
            recommendations.append(
                "Check whether the vulnerability is present and "
                "whether a patch or mitigation is available."
            )

        if asset_criticality and asset_criticality.lower() == "critical":
            recommendations.append(
                "Prioritize reviewing the connected critical asset "
                "and its access paths."
            )

        investigations.append({
            "alert_id": row[0],
            "severity": severity,
            "description": row[2],
            "connected_entities": {
                "device": device,
                "vulnerability": vulnerability,
                "vulnerability_severity": vulnerability_severity,
                "identity": identity,
                "asset": asset,
                "asset_criticality": asset_criticality
            },
            "findings": findings,
            "recommended_actions": recommendations
        })

    # 6. Return the investigation report
    return {
        "status": "success",
        "investigation": investigations,
        "evidence_note": (
            "Findings are based on synthetic graph relationships. "
            "They do not prove exploitation or a confirmed attack."
        ),
        "actions_executed": False
    }


# Run a local test when this file is executed directly
if __name__ == "__main__":
    report = investigate_alert("ALT-002")

    print("\n===== CyberGraph AI Investigation =====")
    print(f"Status: {report['status']}")

    for item in report.get("investigation", []):
        print(f"\nAlert: {item['alert_id']}")
        print(f"Severity: {item['severity']}")

        print("\nFindings:")
        for finding in item["findings"]:
            print(f"- {finding}")

        print("\nRecommended actions:")
        for action in item["recommended_actions"]:
            print(f"- {action}")

    print("\nActions executed:", report["actions_executed"])
    print("\nEvidence note:", report["evidence_note"])