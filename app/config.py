import os
from dotenv import load_dotenv

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(BASE_DIR, "environnements", ".env"))

class Config:
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "default")
    JWT_ALGORITHM = "RS256"
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
    FIREBASE_API_KEY = os.getenv("Firebase_API_KEY")
    FIREBASE_CREDENTIALS_PATH = os.path.join(BASE_DIR, "environnements", "cereskeeper-firebase-adminsdk-fbsvc-2f1b5677b7.json")
    FIREBASE_STORAGE_BUCKET = "cannaxion-cf460.appspot.com"