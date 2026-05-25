import os
from dotenv import load_dotenv

# Ensure local `.env` changes take effect even if the shell already exported
# stale values (e.g. an old GOOGLE_CLOUD_LOCATION).
load_dotenv(override=True)

PROJECT_ID  = os.getenv("GOOGLE_CLOUD_PROJECT", "satark-ai-492219")
LOCATION    = os.getenv("GOOGLE_CLOUD_LOCATION", "global")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")

# Determine whether to use Vertex AI or Developer API key mode.
# By default, use Developer API key mode if GEMINI_API_KEY is available (since GCP project billing is disabled).
use_vertex_str = os.getenv("GOOGLE_GENAI_USE_VERTEXAI")
if use_vertex_str is not None:
    USE_VERTEXAI = use_vertex_str.lower() in ("true", "1")
else:
    USE_VERTEXAI = not bool(GEMINI_API_KEY)

# Ensure environment variables are synchronized.
if USE_VERTEXAI:
    os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "true"
    os.environ["GOOGLE_CLOUD_PROJECT"] = PROJECT_ID
    os.environ["GOOGLE_CLOUD_LOCATION"] = LOCATION
    
    MODEL_PRO        = "gemini-3.5-flash"
    MODEL_PRO_TOOLS  = "gemini-3.5-flash"
    MODEL_FLASH      = "gemini-3.5-flash"
    MODEL_LIVE       = os.getenv("MODEL_LIVE", "publishers/google/models/gemini-live-2.5-flash-native-audio")
    MODEL_EMBEDDING  = os.getenv("MODEL_EMBEDDING", "text-embedding-005")
else:
    os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "false"
    
    MODEL_PRO        = "gemini-3.5-flash"
    MODEL_PRO_TOOLS  = "gemini-3.5-flash"
    MODEL_FLASH      = "gemini-3.5-flash"
    MODEL_LIVE       = os.getenv("MODEL_LIVE", "gemini-2.5-flash-native-audio-latest")
    MODEL_EMBEDDING  = os.getenv("MODEL_EMBEDDING", "gemini-embedding-001")

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

def get_genai_client():
    """Returns an initialized google-genai Client depending on configured credentials."""
    from google import genai
    if USE_VERTEXAI:
        return genai.Client(vertexai=True, project=PROJECT_ID, location=LOCATION)
    else:
        # Fallback/default to API key mode
        return genai.Client(api_key=GEMINI_API_KEY)