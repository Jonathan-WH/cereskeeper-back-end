from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import jwt_required, get_jwt_identity, JWTManager, verify_jwt_in_request
import datetime
import firebase_admin
from firebase_admin import auth, firestore, credentials
import os
import re

# 📌 Récupère le chemin du dossier contenant ce fichier
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# 🔥 Initialise Firebase avec les credentials JSON
cred = credentials.Certificate(os.path.join(BASE_DIR, "environnements", "cereskeeper-firebase-adminsdk-fbsvc-2f1b5677b7.json"))
firebase_admin.initialize_app(cred)

# 📂 Connexion à Firestore
db = firestore.client()

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

# 🔐 Configuration du JWT Secret pour accepter Firebase Tokens (RS256)
app.config["JWT_SECRET_KEY"] = "secret_key_to_change"
app.config["JWT_ALGORITHM"] = "RS256"  # ⚠️ Permet l'algorithme RS256 de Firebase
jwt = JWTManager(app)

#Before the request
@app.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        return '', 200, {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS, DELETE, PUT",
            "Access-Control-Allow-Headers": "Content-Type, Authorization"
        }

# Route de connexion depuis register
@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.json
        print("📥 Données reçues:", data)

        if not data:
            print("❌ Erreur : Données non reçues")
            return jsonify({"error": "No data received"}), 400

        email = data.get('email')
        password = data.get('password')
        username = data.get('username')

        if not email or not password or not username:
            print("❌ Erreur : Champs manquants")
            return jsonify({"error": "Missing required fields"}), 400

        # 🔍 Vérification de l'email avec une REGEX
        email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
        if not re.match(email_regex, email):
            print("❌ Erreur : Email invalide")
            return jsonify({"error": "Invalid email format"}), 400

        # 🔍 Vérification du mot de passe avec une REGEX
        password_regex = r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
        if not re.match(password_regex, password):
            print("❌ Erreur : Mot de passe invalide")
            return jsonify({"error": "Password must be at least 8 characters long, contain one uppercase letter, one number, and one special character."}), 400

        # 🔍 Vérification du username (min 8 caractères)
        if len(username) < 8:
            print("❌ Erreur : Username trop court")
            return jsonify({"error": "Username must be at least 8 characters long"}), 400

        # 🔍 Vérifier si l'email est déjà utilisé dans Firebase
        try:
            auth.get_user_by_email(email)
            print(f"❌ Erreur : Email {email} déjà utilisé dans Firebase")
            return jsonify({"error": "Email already exists"}), 400
        except:
            print(f"✅ L'email {email} n'existe PAS encore dans Firebase, création en cours...")

        # 🔍 Vérifier si le username est déjà utilisé dans Firestore
        user_query = db.collection("users").where("username", "==", username).stream()
        if any(user_query):
            print(f"❌ Erreur : Username '{username}' déjà utilisé")
            return jsonify({"error": "Username already exists"}), 400

        # 🔥 Création de l'utilisateur Firebase
        print(f"🛠️ Création Firebase en cours pour {email}...")
        user = auth.create_user(email=email, password=password, display_name=username)
        print(f"✅ Firebase OK : {user.uid}")

        # 📂 Ajout dans Firestore
        print(f"🛠️ Ajout Firestore en cours...")
        db.collection("users").document(user.uid).set({
            "uid": user.uid,
            "email": email,
            "username": username,
            "createdAt": datetime.datetime.now(datetime.timezone.utc).isoformat()
        })
        print("✅ Firestore OK")

        return jsonify({"message": "User registered successfully", "uid": user.uid}), 201

    except Exception as e:
        print(f"❌ Erreur inattendue : {e}")
        return jsonify({"error": str(e)}), 400


# ✅ 📌 Route de connexion (Renvoie le token Firebase au frontend)
@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.json
        email = data.get('email')
        password = data.get('password')

        # 🔥 Vérifier l'utilisateur Firebase
        user_record = auth.get_user_by_email(email)

        # ✅ Génération du Token Firebase (C'est le Front qui le stocke et l'envoie dans chaque requête)
        return jsonify({
            "message": "Login successful",
            "uid": user_record.uid
        }), 200

    except Exception as e:
        return jsonify({"error": "Invalid credentials"}), 401


# ✅ 📌 Route protégée : /home-connected
@app.route('/home-connected', methods=['GET'])
def home_connected():
    auth_header = request.headers.get('Authorization')

    if not auth_header:
        return jsonify({"error": "Missing Authorization Header"}), 401

    token = auth_header.split(" ")[1]  # 🔥 Récupère le token Firebase (Bearer <token>)
    
    try:
        decoded_token = auth.verify_id_token(token)  # 🔥 Vérifie le token avec Firebase
        current_user_id = decoded_token['uid']

        # 📂 Récupère les infos de l'utilisateur depuis Firestore
        user_ref = db.collection("users").document(current_user_id)
        user_doc = user_ref.get()

        if user_doc.exists:
            user_data = user_doc.to_dict()
            return jsonify({"message": "Welcome to home-connected", "user": user_data}), 200
        else:
            return jsonify({"error": "User not found"}), 404

    except Exception as e:
        return jsonify({"error": str(e)}), 401


# ✅ 📌 Route d'accueil
@app.route("/", methods=["GET"])
def home():
    return jsonify({"message": "Welcome to CeresKeeper API!"}), 200


# ✅ Lancer le serveur
if __name__ == '__main__':
    app.run(debug=True)