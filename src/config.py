import os
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key")
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"

# For localhost testing (HTTP), this will be False
# For production deployment (HTTPS), set PRODUCTION=true in .env
SESSION_COOKIE_SECURE = os.environ.get("PRODUCTION", "false").lower() == "true"

# Corbado configuration
CORBADO_PROJECT_ID = os.environ.get("CORBADO_PROJECT_ID", "pro-XXX")
CORBADO_API_SECRET = os.environ.get("CORBADO_API_SECRET", "corbado1_XXX")
CORBADO_FRONTEND_API = os.environ.get("CORBADO_FRONTEND_API", "")
CORBADO_BACKEND_API = os.environ.get("CORBADO_BACKEND_API", "")