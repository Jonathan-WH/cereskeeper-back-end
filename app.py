from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager
import datetime
import firebase_admin
from firebase_admin import auth, firestore, credentials, storage
import os
import re
import base64
from PIL import Image
import io
import requests as py_request
import requests
from dotenv import load_dotenv

# 📌 Récupérer le chemin du dossier contenant ce fichier
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# 🔥 Charger les variables d'environnemen
load_dotenv(os.path.join(BASE_DIR, "environnements", ".env"))

# 🔥 Initialise Firebase avec les credentials JSON
cred = credentials.Certificate(os.path.join(BASE_DIR, "environnements", "cereskeeper-firebase-adminsdk-fbsvc-2f1b5677b7.json"))
firebase_admin.initialize_app(cred, {
    "storageBucket": "cannaxion-cf460.appspot.com"
})

# 📂 Connexion à Firestore
db = firestore.client()

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

@app.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        return '', 200, {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS, DELETE, PUT",
            "Access-Control-Allow-Headers": "Content-Type, Authorization"
        }

# 🔐 Configuration du JWT Secret pour accepter Firebase Tokens (RS256)
app.config["JWT_SECRET_KEY"] = "secret_key_to_change"
app.config["JWT_ALGORITHM"] = "RS256"
jwt = JWTManager(app)

# 🔑 Clé API OpenAI et firebase stockée en variable d'environnement
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
FIREBASE_API_KEY = os.getenv("Firebase_API_KEY")
print(f"🔑 Clé API Firebase chargée: {FIREBASE_API_KEY}")

# ✅ 📌 Route d'inscription (Register)
@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.json
        email = data.get('email')
        password = data.get('password')
        username = data.get('username')

        if not email or not password or not username:
            return jsonify({"error": "Missing required fields"}), 400

        # 🔍 Vérification du format de l'email
        email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
        if not re.match(email_regex, email):
            return jsonify({"error": "Invalid email format"}), 400

        # 🔍 Vérification du format du mot de passe
        password_regex = r'^(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$'
        if not re.match(password_regex, password):
            return jsonify({"error": "Password must contain at least 8 characters, one uppercase letter, one number, and one special character."}), 400

        # 🔍 Vérification du username
        if len(username) < 8:
            return jsonify({"error": "Username must be at least 8 characters long"}), 400

        # Vérifier si l'email est déjà utilisé
        try:
            auth.get_user_by_email(email)
            return jsonify({"error": "Email already exists"}), 400
        except:
            pass

        # Vérifier si le username est déjà utilisé
        username_query = db.collection("users").where("username", "==", username).stream()
        if any(username_query):
            return jsonify({"error": "Username already exists"}), 400

        # 🔥 Création de l'utilisateur Firebase
        user = auth.create_user(email=email, password=password, display_name=username)
        uid = user.uid

        # 📂 Ajout dans Firestore
        db.collection("users").document(uid).set({
            "uid": uid,
            "email": email,
            "username": username,
            "createdAt": datetime.datetime.now(datetime.timezone.utc).isoformat()
        })

        # 🔥 Connexion automatique pour récupérer un idToken
        firebase_signin_url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={FIREBASE_API_KEY}"
        payload = {"email": email, "password": password, "returnSecureToken": True}
        response = py_request.post(firebase_signin_url, json=payload)
        response_data = response.json()

        if response.status_code != 200:
            return jsonify({"error": "Account created but login failed."}), 500

        return jsonify({
            "message": "User registered successfully",
            "uid": uid,
            "idToken": response_data.get("idToken")
        }), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ✅ 📌 Route de connexion (Login) avec Firebase Token
@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.json
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            return jsonify({"error": "Missing email or password"}), 400

        print(f"📤 Tentative de connexion pour: {email}")

        # 🔥 Vérification de la clé API Firebase
        api_key = os.getenv("Firebase_API_KEY")
        if not api_key:
            print("❌ Erreur : Clé API Firebase manquante")
            return jsonify({"error": "Internal server error - Firebase API key missing"}), 500

        # 📡 Appel à Firebase pour vérifier les credentials
        firebase_signin_url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={api_key}"
        payload = {
            "email": email,
            "password": password,
            "returnSecureToken": True
        }

        response = requests.post(firebase_signin_url, json=payload)
        response_data = response.json()

        if response.status_code != 200:
            print(f"❌ Erreur Firebase: {response_data}")
            return jsonify({"error": "Invalid email or password"}), 401

        # ✅ Connexion réussie : on récupère le token Firebase
        id_token = response_data.get("idToken")
        uid = response_data.get("localId")

        print(f"✅ Connexion réussie pour {email}, UID: {uid}")

        return jsonify({
            "message": "Login successful",
            "uid": uid,
            "idToken": id_token
        }), 200

    except Exception as e:
        print(f"❌ ERREUR INATTENDUE DANS LOGIN: {e}")
        return jsonify({"error": str(e)}), 500

# ✅ 📌 Route protégée : /home-connected
@app.route('/home-connected', methods=['GET'])
def home_connected():
    auth_header = request.headers.get('Authorization')

    if not auth_header:
        return jsonify({"error": "Missing Authorization Header"}), 401

    token = auth_header.split(" ")[1]
    
    try:
        decoded_token = auth.verify_id_token(token)
        current_user_id = decoded_token['uid']

        user_ref = db.collection("users").document(current_user_id)
        user_doc = user_ref.get()

        if user_doc.exists:
            return jsonify({
                "message": "Welcome to home-connected",
                "user": user_doc.to_dict()
            }), 200
        else:
            return jsonify({"error": "User not found"}), 404

    except Exception as e:
        return jsonify({"error": str(e)}), 401
    


# ✅ 📌 Route d'upload d'image vers Firebase Storage
def upload_to_firebase(image_data, filename):
    if not image_data:
        print("❌ Image data is empty.")
        return None

    print(f"📏 Taille de l'image avant upload : {len(image_data)} octets")
    
    bucket = storage.bucket()
    blob = bucket.blob(f"plants/{filename}")
    blob.upload_from_string(image_data, content_type="image/jpeg")
    blob.make_public()  # Rendre l'image accessible publiquement (à sécuriser plus tard)
    return blob.public_url  # ✅ Retourne l'URL Firestore

# 📌 Convertir une image en Base64 (cas où on envoie l'image directement à OpenAI sans stocker)
def encode_image(image_file):
    return base64.b64encode(image_file.read()).decode("utf-8")

def resize_image(image_data, max_size=1024, quality=100):
    # Ouvrir l'image avec Pillow
    image = Image.open(io.BytesIO(image_data))

    # ✅ Convertir en mode RGB si l'image est en RGBA
    if image.mode == 'RGBA':
        image = image.convert('RGB')

    # 🔍 Redimensionner en conservant les proportions
    image.thumbnail((max_size, max_size), Image.LANCZOS)

    # Convertir l'image en bytes après redimensionnement
    img_byte_array = io.BytesIO()
    image.save(img_byte_array, format='JPEG', quality=quality)
    return img_byte_array.getvalue()

# ✅ 📌 Route d'upload d'image
@app.route('/upload-image', methods=['POST'])
def upload_image():
    try:
        if 'image' not in request.files:
            return jsonify({"error": "No image provided"}), 400
        
        image_file = request.files['image']
        filename = f"plant_{datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d%H%M%S')}.jpg"

        # 📥 Lire l'image brute
        image_data = image_file.read()

        # 🔥 Redimensionner et convertir en Base64
        resized_image_data = resize_image(image_data)
        base64_encoded_image = encode_image(io.BytesIO(resized_image_data))

        print(f"📥 Encoded image size: {len(base64_encoded_image)} bytes")

        # 📂 Uploader sur Firebase Storage
        image_url = upload_to_firebase(resized_image_data, filename)
        return jsonify({"image_url": image_url})

    except Exception as e:
        print("❌ Erreur inattendue dans upload_image:", str(e))
        return jsonify({"error": str(e)}), 500

# ✅ 📌 Route pour analyser la plante via GPT-4o
@app.route('/analyze-plant', methods=['POST'])
def analyze_plant():
    try:
        data = request.json
        print("📥 Data received for analysis:", data)

        image_urls = data.get('image_urls', [])
        plant_name = data.get('plant_name', 'Unknown')
        plant_context = data.get('plant_context', 'No details provided.')

        if not image_urls:
            return jsonify({"error": "No image URLs provided"}), 400

        # 🔍 Construire la requête pour GPT-4o
        image_data = [{"type": "image_url", "image_url": {"url": url}} for url in image_urls]
        messages = [
            {"role": "user", "content": [
                {"type": "text", "text": f"Identify the plant problem based on these images. Name: {plant_name}. Context: {plant_context}"},
                *image_data
            ]}
        ]

        payload = {
            "model": "gpt-4o",
            "messages": messages,
            "max_tokens": 300
        }

        headers = {
            "Authorization": f"Bearer {OPENAI_API_KEY}",
            "Content-Type": "application/json"
        }

        print("📡 Sending request to OpenAI with payload:", payload)

        # 📡 Envoyer la requête à OpenAI
        response = py_request.post("https://api.openai.com/v1/chat/completions", json=payload, headers=headers)

        if response.status_code != 200:
            print("❌ OpenAI response error:", response.json())
            return jsonify({"error": "OpenAI request failed", "details": response.json()}), 500

        # ✅ Retourner l'analyse
        result = response.json()
        analysis_text = result['choices'][0]['message']['content']

        return jsonify({"analysis": analysis_text, "image_urls": image_urls})

    except Exception as e:
        print("❌ Unexpected error in analyze_plant:", str(e))
        return jsonify({"error": str(e)}), 500
    
@app.route('/update-profile', methods=['POST'])
def update_profile():
    try:
        # 📌 Vérifier le token JWT Firebase dans l'en-tête de la requête
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return jsonify({"error": "Missing Authorization Header"}), 401

        token = auth_header.split(" ")[1]
        decoded_token = auth.verify_id_token(token)
        uid = decoded_token['uid']

        # 📌 Récupérer les données envoyées depuis le frontend
        data = request.json
        email = data.get('email')
        username = data.get('username')
        password = data.get('password')
        confirm_password = data.get('confirmPassword')

        # ✅ Récupérer l'utilisateur Firebase
        user_ref = db.collection("users").document(uid)
        user_doc = user_ref.get()

        if not user_doc.exists:
            return jsonify({"error": "User not found"}), 404

        # 📌 Récupérer les données actuelles de l'utilisateur
        user_data = user_doc.to_dict()
        current_email = user_data.get("email")
        current_username = user_data.get("username")

        # 📌 Préparer les mises à jour
        updates = {}

        # 🔍 Vérification & Mise à jour de l'email
        if email and email != current_email:
            email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
            if not re.match(email_regex, email):
                return jsonify({"error": "Invalid email format"}), 400

            try:
                auth.get_user_by_email(email)  # 🔍 Vérifie si l'email est déjà utilisé
                return jsonify({"error": "Email already exists"}), 400
            except firebase_admin.auth.UserNotFoundError:
                # ✅ Si l'email n'existe pas déjà, on le met à jour
                auth.update_user(uid, email=email)
                updates['email'] = email

        # 🔍 Vérification & Mise à jour du username
        if username and username != current_username:
            username_regex = r'^[a-zA-Z0-9]{8,}$'  # Min 8 caractères, lettres et chiffres uniquement
            if not re.match(username_regex, username):
                return jsonify({"error": "Username must be at least 8 characters long and contain only letters and numbers"}), 400

            # Vérifier si le username est déjà pris
            username_query = db.collection("users").where("username", "==", username).stream()
            if any(username_query):
                return jsonify({"error": "Username already exists"}), 400

            auth.update_user(uid, display_name=username)
            updates['username'] = username

        # 🔍 Vérification & Mise à jour du mot de passe
        if password:
            password_regex = r'^(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$'
            if not re.match(password_regex, password):
                return jsonify({"error": "Password must be at least 8 characters long and contain at least one uppercase letter, one number, and one special character."}), 400

            if password != confirm_password:
                return jsonify({"error": "Passwords do not match"}), 400

            auth.update_user(uid, password=password)

        # 📂 Mettre à jour Firestore uniquement si des changements ont été faits
        if updates:
            user_ref.update(updates)

        return jsonify({"message": "Profile updated successfully"}), 200

    except firebase_admin.auth.EmailAlreadyExistsError:
        return jsonify({"error": "Email already exists"}), 400

    except Exception as e:
        print("❌ Error updating profile:", str(e))
        return jsonify({"error": str(e)}), 500

# ✅ 📌 Route d'accueil
@app.route("/", methods=["GET"])
def home():
    return jsonify({"message": "Welcome to CeresKeeper API!"}), 200

# ✅ Lancer le serveur
if __name__ == '__main__':
    app.run(debug=True)