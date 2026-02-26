import json
from openai import OpenAI
from config import GROQ_API_KEY
from core.utils import log_message

def generate_ai_analysis(scan_data):
    """
    Sends scan results to Groq for contextual cybersecurity analysis.
    """
    if not GROQ_API_KEY:
        log_message("AI Analysis skipped: GROQ_API_KEY not found in environment.")
        return "AI Analysis Unavailable: GROQ_API_KEY missing. Please set the environment variable."

    try:
        client = OpenAI(
            api_key=GROQ_API_KEY,
            base_url="https://api.groq.com/openai/v1"
        )
        
        system_prompt = (
            "You are a senior cybersecurity analyst. Only reason based on provided data. "
            "Do NOT invent vulnerabilities. Do NOT hallucinate CVEs. Do NOT overclaim exploitability."
        )
        
        user_prompt = f"""Analyze the following scan result and provide a professional report with the following sections formatted in Markdown:
1. Executive summary
2. Risk explanation
3. Potential attack vectors
4. Recommended remediation steps
5. Defensive hardening advice

Scan Data:
{json.dumps(scan_data, indent=2)}
"""

        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.3, # Keep it deterministic and factual
            max_tokens=1500
        )
        
        analysis = response.choices[0].message.content
        return analysis
        
    except Exception as e:
        err_msg = f"AI Analysis failed: {str(e)}"
        log_message(err_msg)
        return err_msg
