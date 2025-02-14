import os
import firebase_admin
from firebase_admin import credentials, auth, firestore

# 📌 Récupère le chemin du dossier contenant ce fichier
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


# 🔥 Charge les credentials Firebase avec un chemin relatif
cred = credentials.Certificate(os.path.join(BASE_DIR, "environnements", "cereskeeper-firebase-adminsdk-fbsvc-2f1b5677b7.json"))

# ✅ Initialisation de Firebase
firebase_admin.initialize_app(cred)

# 📂 Connexion à Firestore
db = firestore.client()