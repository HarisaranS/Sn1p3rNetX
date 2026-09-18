"""
attack_story.py — Generates AI-powered attack narratives.
"""
import os

def generate_attack_story(host_data: dict) -> dict:
    return quick_attack_story(host_data)

def quick_attack_story(host_data: dict) -> dict:
    ports = host_data.get("open_ports", [])
    story = "Day 1: Attacker scans the network and finds exposed services.\n"
    if any(p in str(ports) for p in ["3389", "3390"]):
        story += "Day 2: Attacker brute forces RDP or exploits a known vulnerability (e.g. BlueKeep) to gain initial access.\n"
    if "3306" in str(ports):
        story += "Day 3: With internal access, the attacker dumps the MySQL database.\n"
    
    return {
        "title": "The Likely Attack Path",
        "narrative": story,
        "kill_chain_steps": ["Reconnaissance", "Initial Access", "Data Exfiltration"],
        "blast_radius": "High",
        "severity": host_data.get("risk_level", "UNKNOWN"),
        "estimated_attack_time_hours": 48
    }

def format_attack_story(story: dict) -> str:
    return f" ATTACK STORY: {story['title']}\n{'-'*40}\n{story['narrative']}"
