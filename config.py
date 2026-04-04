import os
from dotenv import load_dotenv
load_dotenv()

PROJECT_ID  = os.getenv("GOOGLE_CLOUD_PROJECT", "satark-ai-492219")
LOCATION    = os.getenv("GOOGLE_CLOUD_LOCATION", "us-central1")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")

# Using Vertex AI with GCP credits — no free tier limits
MODEL_PRO        = "gemini-2.5-pro"
MODEL_PRO_TOOLS  = "gemini-2.5-pro"
MODEL_FLASH      = "gemini-2.5-flash"
MODEL_LIVE       = os.getenv("MODEL_LIVE", "publishers/google/models/gemini-live-2.5-flash-native-audio")
MODEL_EMBEDDING  = "gemini-embedding-2-preview"

# Compatibility aliases for ADK-based modules
GEMINI_PRO_MODEL = os.getenv("GEMINI_PRO_MODEL", MODEL_PRO)
GEMINI_FLASH_MODEL = os.getenv("GEMINI_FLASH_MODEL", MODEL_FLASH)
GEMINI_LIVE_MODEL = os.getenv("GEMINI_LIVE_MODEL", MODEL_LIVE)

ALLOYDB_REGION   = os.getenv("ALLOYDB_REGION",   "asia-south1")
ALLOYDB_CLUSTER  = os.getenv("ALLOYDB_CLUSTER",  "scamguard-db")
ALLOYDB_INSTANCE = os.getenv("ALLOYDB_INSTANCE", "primary-instance")
ALLOYDB_DATABASE = os.getenv("ALLOYDB_DATABASE", "scamguard")
ALLOYDB_USER     = os.getenv("ALLOYDB_USER",     "postgres")
ALLOYDB_PASSWORD = os.getenv("ALLOYDB_PASSWORD", "")

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")