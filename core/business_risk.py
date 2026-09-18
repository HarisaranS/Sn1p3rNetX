"""
business_risk.py — Translates technical risk into business impact metrics.
"""

def estimate_breach_cost(host_data: dict, sector: str = 'general') -> dict:
    risk_score = host_data.get("risk_score", 0)
    
    base_cost = 4500000
    if sector.lower() == 'healthcare':
        base_cost = 10900000
    elif sector.lower() == 'finance':
        base_cost = 6100000
    elif sector.lower() == 'retail':
        base_cost = 3400000
    
    multiplier = risk_score / 100.0
    
    likely_cost = int(base_cost * multiplier)
    min_cost = int(likely_cost * 0.7)
    max_cost = int(likely_cost * 1.5)
    
    prob = min(100, int(risk_score * 0.8))
    
    level = "LOW"
    if risk_score >= 90: level = "CATASTROPHIC"
    elif risk_score >= 75: level = "CRITICAL"
    elif risk_score >= 45: level = "HIGH"
    elif risk_score >= 20: level = "MEDIUM"
    
    return {
        "estimated_breach_cost_usd": {"min": min_cost, "max": max_cost, "likely": likely_cost},
        "estimated_downtime_hours": int(24 * multiplier * 2),
        "data_records_at_risk": int(50000 * multiplier),
        "regulatory_fines_usd": int(1000000 * multiplier),
        "reputation_impact": level,
        "cyber_insurance_impact": "Likely to void policy" if risk_score > 75 else "May increase premiums",
        "breach_probability_pct": prob,
        "business_risk_level": level
    }

def generate_executive_brief(host_data: dict, sector: str = 'general') -> str:
    res = estimate_breach_cost(host_data, sector)
    return f"""EXECUTIVE BRIEFING
Based on the current security posture, the business faces a {res['business_risk_level']} risk level.
There is a {res['breach_probability_pct']}% probability of a breach in the near term.
Estimated cost of a breach is ${res['estimated_breach_cost_usd']['likely']:,} with potential regulatory fines of ${res['regulatory_fines_usd']:,}."""
