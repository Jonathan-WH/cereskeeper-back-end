from flask import Flask
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from firebase_admin import credentials, initialize_app
from .config import Config

import firebase_admin
from firebase_admin import firestore, storage

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # 🔐 CORS & JWT
    CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)
    JWTManager(app)

    # 🔥 Firebase init
    cred = credentials.Certificate(Config.FIREBASE_CREDENTIALS_PATH)
    firebase_admin.initialize_app(cred, {
        "storageBucket": Config.FIREBASE_STORAGE_BUCKET
    })

    # 📦 Import et enregistrement des routes
    from app.routes import register_routes
    register_routes(app)

    return app