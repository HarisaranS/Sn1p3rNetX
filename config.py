import os

# Configuration settings
VERSION = "2.0"
DB_FILE = "sn1p3rnetx_history.db"

# LLM Config
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "<your-api-key>")

# Report Settings
DEFAULT_REPORT_FORMAT = "text"
