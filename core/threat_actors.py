"""
threat_actors.py — Maps vulnerabilities and ports to known threat actors.
"""

ACTORS = [
    {
        "name": "APT41",
        "origin": "China",
        "motivation": "Espionage & Financial",
        "target_ports": [3389, 445, 1433, 3306],
        "sophistication": 5,
        "description": "Prolific Chinese state-sponsored cyber threat group."
    },
    {
        "name": "LockBit",
        "origin": "Russia/CIS",
        "motivation": "Financial (Ransomware)",
        "target_ports": [3389, 139, 445],
        "sophistication": 4,
        "description": "Ransomware-as-a-service (RaaS) operation."
    },
    {
        "name": "Sandworm",
        "origin": "Russia",
        "motivation": "Destruction / Sabotage",
        "target_ports": [22, 443, 80],
        "sophistication": 5,
        "description": "Russian GRU cyber military unit."
    }
]

def profile_threat_actors(host_data: dict) -> list[dict]:
    matched = []
    ports = [int(str(p).split("/")[0]) for p in host_data.get("open_ports", []) if str(p).split("/")[0].isdigit()]
    
    for actor in ACTORS:
        matches = set(actor["target_ports"]).intersection(ports)
        if matches:
            a = actor.copy()
            a["match_score"] = len(matches) * 20
            a["match_reasons"] = [f"Targets open port {p}" for p in matches]
            matched.append(a)
            
    return sorted(matched, key=lambda x: x["match_score"], reverse=True)

def get_threat_summary(actors: list) -> str:
    if not actors:
        return "No known threat actor profiles match the current footprint."
    names = [a["name"] for a in actors[:3]]
    return f"This attack surface matches the TTPs of {len(actors)} known threat groups, including {', '.join(names)}."
