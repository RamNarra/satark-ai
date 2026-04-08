import os
from dotenv import load_dotenv

# Ensure local `.env` changes take effect even if the shell already exported
# stale values (e.g. an old GOOGLE_CLOUD_LOCATION).
load_dotenv(override=True)

PROJECT_ID  = os.getenv("GOOGLE_CLOUD_PROJECT", "satark-ai-492219")

# Gemini 3 preview models are served from the global Vertex endpoint.
LOCATION    = os.getenv("GOOGLE_CLOUD_LOCATION", "global")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")

# Ensure ADK and google-genai clients default to Vertex AI mode.
os.environ.setdefault("GOOGLE_GENAI_USE_VERTEXAI", "true")
os.environ.setdefault("GOOGLE_CLOUD_PROJECT", PROJECT_ID)
os.environ.setdefault("GOOGLE_CLOUD_LOCATION", LOCATION)

# Using Vertex AI with GCP credits — no free tier limits
# Default everything to the fast, agent-friendly preview model.
MODEL_PRO        = "gemini-3-flash-preview"
MODEL_PRO_TOOLS  = "gemini-3-flash-preview"
MODEL_FLASH      = "gemini-3-flash-preview"
MODEL_LIVE       = os.getenv("MODEL_LIVE", "publishers/google/models/gemini-live-2.5-flash-native-audio")
MODEL_EMBEDDING  = os.getenv("MODEL_EMBEDDING", os.getenv("EMBEDDING_MODEL", "text-embedding-005"))

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