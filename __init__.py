from flask import Flask
from flask_cors import CORS
from dotenv import load_dotenv
import os
import firebase_admin
from firebase_admin import credentials, firestore, storage
 # Enregistrement des routes
from app.routes import register_routes


# Chargement des variables d’environnement
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, "environnements", ".env"))

# Initialisation Firebase
cred = credentials.Certificate(os.path.join(BASE_DIR, "environnements", "cereskeeper-firebase-adminsdk-fbsvc-2f1b5677b7.json"))
firebase_admin.initialize_app(cred, {
    "storageBucket": "cannaxion-cf460.appspot.com"
})
db = firestore.client()

# Application Flask
def create_app():
    app = Flask(__name__)
    CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

    register_routes(app)

    return app