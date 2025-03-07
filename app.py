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
import json
import pytz


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

# Config Meteomatics (à remplacer par tes credentials)
METEOMATICS_USERNAME = os.getenv("METEOMATICS_USERNAME")
METEOMATICS_PASSWORD = os.getenv("METEOMATICS_PASSWORD")
METEOMATICS_BASE_URL = "https://api.meteomatics.com"
print(f"🔑 Meteomatics Credentials: {METEOMATICS_USERNAME}, {METEOMATICS_PASSWORD}")

# ✅ 📌 Route d'inscription (Register)
@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.json
        email = data.get('email').strip()
        password = data.get('password').strip()
        username = data.get('username').strip()
        confirm_password = data.get('confirmPassword').strip()

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
        
         # Vérifier que le mot de passe et la confirmation correspondent
        if password != confirm_password:
            return jsonify({"error": "Passwords do not match"}), 400

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
        email = data.get('email').strip()
        password = data.get('password').strip()

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

@app.route('/analyze-plant', methods=['POST'])
def analyze_plant():
    try:
        data = request.json
        print("📥 Data received for analysis:", data)

        image_urls = data.get('image_urls', [])
        environment = data.get('environment', 'Not specified')
        variety = data.get('variety', 'Unknown')
        symptoms = data.get('symptoms', 'No symptoms reported')
        user_id = data.get('user_id')  # 🔥 Récupération de l'UID utilisateur

        if not image_urls:
            return jsonify({"error": "No image URLs provided"}), 400

        # 🔍 Construire la requête pour GPT-4o
        image_data = [{"type": "image_url", "image_url": {"url": url}} for url in image_urls]

        messages = [
      {"role": "user", "content": [
        {"type": "text", "text": f"""
        You are an experienced horticulturist.
        Analyze the following images to detect any potential issues with the plant.
        • Environment: {environment}
        • Variety: {variety}
        • Observed symptoms: {symptoms}

        If a problem is detected, provide a clear response with:
        • 📌 Name of the issue
        • 🛠 Detailed explanation of the problem and its causes
        • 🚨 Possible consequences if left untreated
        • 🏡 100% organic and biological solution
        • 🧪 Chemical solution
        • 🌿 Hybrid solution (organic + chemical)

        If no issue is detected, simply respond: "No problems detected. Try a new analysis with different photos."

        📌 **Response Format (Important!)**:
        - Provide the answer **strictly in valid Ionic HTML format** using `<ion-card>`, `<ion-card-header>`, `<ion-card-title>`, and `<ion-card-content>`.
        - Do **not** include explanations outside of this structure.
        📌 **Response Format (Important!):**
        - **Do not use Markdown. Do not format text with `**bold**`. Provide plain HTML only.**
        - Example response format:
        
        ```html
        <ion-card color="success" mode="ios">
            <ion-card-header>
                <ion-card-title>Plant Analysis Result</ion-card-title>
                <ion-card-subtitle>Healthy Plant</ion-card-subtitle>
            </ion-card-header>
            <ion-card-content>
                No problems detected. Try a new analysis with different photos.
            </ion-card-content>
        </ion-card>

       <ion-card color="danger" class="card-analyse" mode="ios">
    <ion-card-header>
      <ion-card-title class="ion-text-center orbitron_medium">
        Detected Issue: Rust Disease
      </ion-card-title>
      <ion-card-subtitle class="ion-text-center subtile-analyse orbitron_medium">
        Fungal Disease
      </ion-card-subtitle>
    </ion-card-header>

    <ion-card-content>
      <ion-list>
        <!-- Description du problème -->
        <ion-item>
          <ion-label>
            <h2 class="orbitron_bold"> What is Rust Disease?</h2>
            <p class="white">
              Rust disease is a fungal infection caused by various species of fungi from the Pucciniales order. 
              It manifests as small, yellow-orange pustules on the undersides of leaves, which later turn brown and release powdery spores. 
              The disease thrives in warm, humid conditions and spreads rapidly through windborne spores that can infect healthy plants. 
              It primarily affects cereal crops, ornamental plants, and some vegetables, reducing their photosynthesis capacity and overall health.
            </p>
          </ion-label>
        </ion-item>

        <!-- Conséquences -->
        <ion-item>
          <ion-label>
            <h2 class="orbitron_bold">Consequences</h2>
            <p class="white">
              If left untreated, rust disease can cause severe defoliation, weakening the plant and making it more susceptible to secondary infections and environmental stress. 
              Affected plants experience reduced photosynthesis, leading to slower growth, lower crop yields, and, in extreme cases, plant death. 
              In agricultural settings, rust infections can result in significant economic losses, particularly in wheat, coffee, and soybean production. 
              The disease can also spread between different plant species, making containment and management crucial for plant health.
            </p>
          </ion-label>
        </ion-item>

        <!-- Solutions -->
        <ion-item>
          <ion-label>
            <h2 class="orbitron_bold">Organic Solution</h2>
            <p class="white">
              The most effective organic approach involves **early detection** and **preventive action**. 
              Remove and destroy infected leaves immediately to prevent further spore dispersal.<br>
              Apply a **neem oil spray** or a **baking soda solution (1 tsp per liter of water)**, which alters the leaf surface pH and inhibits fungal growth.<br>
              Use a **garlic or horsetail tea spray**, known for their natural antifungal properties.<br>
              Improve plant spacing and air circulation to reduce humidity and fungal spread.<br>
              Enhance soil health by adding **compost tea or seaweed extracts**, which boost plant immunity.
            </p>
          </ion-label>
        </ion-item>

        <ion-item>
          <ion-label>
            <h2 class="orbitron_bold">Chemical Solution</h2>
            <p class="white">
              Use a **fungicide containing myclobutanil, propiconazole, or tebuconazole**, as these are highly effective against rust fungi.<br>
              Follow manufacturer guidelines strictly, as overuse can lead to **fungal resistance**.<br>
              Apply the fungicide in **early morning or late evening** to prevent leaf burn and maximize absorption.<br>
              Rotate between different fungicide classes to prevent the fungi from developing resistance.
            </p>
          </ion-label>
        </ion-item>

        <ion-item>
          <ion-label>
            <h2 class="orbitron_bold">Hybrid Solution</h2>
            <p class="white">
              Begin treatment with **neem oil** or **baking soda spray** for mild infections.<br>
              If the infection progresses, alternate between a **low-toxicity fungicide (copper-based)** and an organic spray to minimize chemical dependency.<br>
              Combine soil amendment strategies like **adding beneficial microbes (mycorrhizae, Trichoderma)** to boost plant defenses.<br>
              Adjust watering schedules to **morning hours only**, reducing humidity levels at night when fungal spores are most active.
            </p>
          </ion-label>
        </ion-item>

        <!-- Prévention -->
        <ion-item lines="none">
          <ion-label>
            <h2 class="orbitron_bold">Prevention Tips</h2>
            <p class="white">
              Prevention is the most effective strategy to **avoid rust outbreaks**:<br>
              Ensure proper **air circulation** around plants by pruning overcrowded foliage.<br>
              Avoid overhead watering, as wet leaves create ideal conditions for fungal spores.<br>
              Regularly **apply compost or organic mulch** to maintain soil health and improve plant immunity.<br>
              Rotate crops every season to prevent rust fungi from persisting in the soil.<br>
              Monitor plants regularly for early signs of infection and take immediate action if needed.
            </p>
          </ion-label>
        </ion-item>
      </ion-list>
    </ion-card-content>
</ion-card>

        ```

        Return the response strictly following this format.
        """},
        *image_data
    ]}
]

        payload = {
            "model": "gpt-4o",
            "messages": messages,
            "max_tokens": 1500
        }

        headers = {
            "Authorization": f"Bearer {OPENAI_API_KEY}",
            "Content-Type": "application/json"
        }

        print("📡 Sending request to OpenAI with payload:", payload)

        response = py_request.post("https://api.openai.com/v1/chat/completions", json=payload, headers=headers)

        if response.status_code != 200:
            print("❌ OpenAI response error:", response.json())
            return jsonify({"error": "OpenAI request failed", "details": response.json()}), 500

        result = response.json()
        analysis_text = result['choices'][0]['message']['content']

         # ✅ Création de l'objet d'analyse
        analysis_data = {
            "title": "🌿 Plant Analysis Report",
            "date": datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),
            "images": image_urls,
            "problem_found": "✅ A problem was detected" if "problem" in analysis_text.lower() else "❌ No major issues detected",
            "analysis": analysis_text 
            }

         # ✅ Stocker l'analyse dans Firestore sous l'utilisateur concerné
        analysis_ref = db.collection("users").document(user_id).collection("analysis").add(analysis_data)

        print(f"✅ Analysis stored in Firestore for user: {user_id}")

        return jsonify(analysis_data), 200

    except Exception as e:
        print("❌ Unexpected error in analyze_plant:", str(e))
        return jsonify({"error": str(e)}), 500
    
@app.route('/update-profile', methods=['POST'])
def update_profile():
    try:
        # ✅ Vérifier le token JWT Firebase dans l'en-tête de la requête
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return jsonify({"error": "Missing Authorization Header"}), 401

        token = auth_header.split(" ")[1]
        decoded_token = auth.verify_id_token(token)
        uid = decoded_token['uid']

        # ✅ Récupérer les données envoyées depuis le frontend
        data = request.json

        # ✅ Vérifier si chaque champ est présent avant d'appliquer `.strip()`
        email = data.get('email', '').strip() if data.get('email') else None
        username = data.get('username', '').strip() if data.get('username') else None
        password = data.get('password') if data.get('password') else None
        confirm_password = data.get('confirmPassword') if data.get('confirmPassword') else None

        # ✅ Récupérer l'utilisateur Firebase
        user_ref = db.collection("users").document(uid)
        user_doc = user_ref.get()

        if not user_doc.exists:
            return jsonify({"error": "User not found"}), 404

        # 📌 Récupérer les données actuelles de l'utilisateur
        user_data = user_doc.to_dict()
        current_email = user_data.get("email")
        current_username = user_data.get("username")

        # 📌 Préparer les mises à jour (on ne modifie que ce qui a changé)
        updates = {}

        # 🔍 Vérification & Mise à jour de l'email uniquement si l'utilisateur l'a changé
        if email and email != current_email:
            email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
            if not re.match(email_regex, email):
                return jsonify({"error": "Invalid email format"}), 400

            try:
                auth.get_user_by_email(email)  # 🔍 Vérifie si l'email est déjà utilisé
                return jsonify({"error": "Email already exists"}), 400
            except firebase_admin.auth.UserNotFoundError:
                auth.update_user(uid, email=email)
                updates['email'] = email

        # 🔍 Vérification & Mise à jour du username uniquement si l'utilisateur l'a changé
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

        # 🔍 Vérification & Mise à jour du mot de passe uniquement si l'utilisateur en a entré un
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
    

# ✅ 📌 Route de récupération de l'historique d'analyses
@app.route('/get-analysis-history', methods=['GET'])
def get_analysis_history():
    try:
        # ✅ Vérifier le token Firebase dans les headers
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return jsonify({"error": "Missing Authorization Header"}), 401

        token = auth_header.split(" ")[1]

        # ✅ Décoder le token Firebase
        decoded_token = auth.verify_id_token(token)
        uid = decoded_token.get('uid')

        if not uid:
            return jsonify({"error": "Invalid token"}), 401

        # ✅ Récupérer les analyses depuis Firestore
        user_ref = db.collection("users").document(uid).collection("analysis")
        analyses = user_ref.stream()

        results = []
        for analysis in analyses:
            data = analysis.to_dict()
            data['id'] = analysis.id
            results.append(data)

        return jsonify(results), 200

    except Exception as e:
        print("❌ Error fetching analysis history:", str(e))
        return jsonify({"error": str(e)}), 500


# ✅ 📌 Route de suppression d'une analyse
import firebase_admin
from firebase_admin import credentials, firestore, storage  # 🔥 Import Firebase Storage

# ✅ 📌 Route de suppression d'une analyse
@app.route('/delete-analysis', methods=['DELETE'])
def delete_analysis():
    try:
        analysis_id = request.args.get('analysisId')
        uid = request.args.get('uid')

        if not analysis_id or not uid:
            print("❌ Missing parameters in request:", request.args)
            return jsonify({"error": "Missing parameters"}), 400

        # 🔥 Récupérer la référence de l'analyse
        analysis_ref = db.collection("users").document(uid).collection("analysis").document(analysis_id)
        analysis_doc = analysis_ref.get()

        if not analysis_doc.exists:
            return jsonify({"error": "Analysis not found"}), 404

        analysis_data = analysis_doc.to_dict()
        image_urls = analysis_data.get("images", [])

        # 🔥 Supprimer les images associées dans Firebase Storage
        bucket = storage.bucket()
        for image_url in image_urls:
           # 🔥 Extraire le chemin après le bucket (le dossier "plants/...")
            path = "/".join(image_url.split('/')[-2:])  # Récupère seulement "plants/nom_du_fichier.jpg"

            blob = bucket.blob(path)

            if blob.exists():
                blob.delete()
                print(f"✅ Image supprimée : {path}")
            else:
                print(f"⚠️ Image introuvable (chemin incorrect) : {path}")

        # 🔥 Supprimer l'analyse de Firestore après la suppression des images
        analysis_ref.delete()

        return jsonify({"message": "Analysis and associated images deleted successfully"}), 200

    except Exception as e:
        print("❌ Error deleting analysis:", str(e))
        return jsonify({"error": str(e)}), 500


@app.route('/create-garden', methods=['POST'])
def create_garden():
    try:
        # ✅ Vérification de l'authentification
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return jsonify({"error": "Missing Authorization Header"}), 401

        token = auth_header.split(" ")[1]
        decoded_token = auth.verify_id_token(token)
        uid = decoded_token.get('uid')

        if not uid:
            return jsonify({"error": "Invalid token"}), 401

        # ✅ Récupération des données du formulaire
        data = request.json
        name = data.get('name')
        start_date = data.get('startDate')
        garden_type = data.get('type')
        postal_code = data.get('postalCode', None)
        location = data.get('location', None)

        if not name or not start_date or not garden_type:
            return jsonify({"error": "Missing required fields"}), 400

        # ✅ Création de l'objet jardin
        garden_data = {
            "name": name,
            "startDate": start_date,
            "type": garden_type,
            "postalCode": postal_code,
            "location": location,
            "createdAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "userId": uid
        }

        # ✅ Ajout du jardin dans Firestore
        garden_ref = db.collection("users").document(uid).collection("gardens").add(garden_data)

        garden_id = garden_ref[1].id  # Récupérer l'ID du jardin créé

        print(f"✅ Garden created: {garden_data}")

        # ✅ Création automatique du dossier "meteo_data" dans le jardin
        weather_collection_ref = db.collection("users").document(uid).collection("gardens").document(garden_id).collection("weather_data")

        weather_collection_ref.add({"message": "Default weather folder created", "createdAt": datetime.datetime.now(datetime.timezone.utc).isoformat()})

        # ✅ Création automatique du dossier "capteurs" dans le jardin
        sensor_collection_ref = db.collection("users").document(uid).collection("gardens").document(garden_id).collection("sensors")

        sensor_collection_ref.add({"message": "Default sensor folder created", "createdAt": datetime.datetime.now(datetime.timezone.utc).isoformat()})

        return jsonify({"message": "Garden created successfully", "gardenId": garden_ref[1].id}), 201

    except Exception as e:
        print("❌ Error creating garden:", str(e))
        return jsonify({"error": str(e)}), 500

@app.route('/get-user-gardens', methods=['GET'])
def get_user_gardens():
    try:
        # ✅ Vérification de l'authentification
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return jsonify({"error": "Missing Authorization Header"}), 401

        token = auth_header.split(" ")[1]
        decoded_token = auth.verify_id_token(token)
        uid = decoded_token.get('uid')

        if not uid:
            return jsonify({"error": "Invalid token"}), 401

        # ✅ Récupérer les jardins de l'utilisateur
        user_ref = db.collection("users").document(uid).collection("gardens")
        gardens = user_ref.stream()

        results = []
        for garden in gardens:
            data = garden.to_dict()
            data['id'] = garden.id
            results.append(data)

        return jsonify(results), 200

    except Exception as e:
        print("❌ Error fetching gardens:", str(e))
        return jsonify({"error": str(e)}), 500

@app.route('/get-garden', methods=['GET'])
def get_garden():
    try:
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return jsonify({"error": "Missing Authorization Header"}), 401

        token = auth_header.split(" ")[1]
        decoded_token = auth.verify_id_token(token)
        uid = decoded_token.get('uid')

        if not uid:
            return jsonify({"error": "Invalid token"}), 401

        garden_id = request.args.get('id')  # ✅ L'ID est d'abord récupéré
        if not garden_id:
            return jsonify({"error": "Missing garden ID"}), 400

        print("📌 Garden ID reçu par Flask:", garden_id)  # ✅ Debug après l'assignation

        # ✅ Récupérer les données du jardin
        garden_ref = db.collection("users").document(uid).collection("gardens").document(garden_id)
        garden_doc = garden_ref.get()

        if not garden_doc.exists:
            return jsonify({"error": "Garden not found"}), 404

        return jsonify(garden_doc.to_dict()), 200

    except Exception as e:
        print("❌ Error fetching garden details:", str(e))
        return jsonify({"error": str(e)}), 500

@app.route('/delete-garden', methods=['DELETE'])
def delete_garden():
    try:
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return jsonify({"error": "Missing Authorization Header"}), 401

        token = auth_header.split(" ")[1]
        decoded_token = auth.verify_id_token(token)
        uid = decoded_token.get('uid')

        if not uid:
            return jsonify({"error": "Invalid token"}), 401

        garden_id = request.args.get('gardenId')
        if not garden_id:
            return jsonify({"error": "Missing garden ID"}), 400

        # ✅ Référence du jardin
        garden_ref = db.collection("users").document(uid).collection("gardens").document(garden_id)

        # ✅ Vérifier si le jardin existe
        if not garden_ref.get().exists:
            return jsonify({"error": "Garden not found"}), 404

        # ✅ Supprimer toutes les sous-collections (sensors)
        sensors_ref = garden_ref.collection("sensors")
        sensors = sensors_ref.stream()
        for sensor in sensors:
            sensors_ref.document(sensor.id).delete()

        # ✅ Supprimer toutes les sous-collections (weather_data)
        weather_ref = garden_ref.collection("weather_data")
        weather_data = weather_ref.stream()
        for weather in weather_data:
            weather_ref.document(weather.id).delete()

        # ✅ Supprimer le jardin après avoir vidé les capteurs
        garden_ref.delete()

        print(f"✅ Garden and sensors deleted: {garden_id}")

        return jsonify({"message": "Garden and associated sensors deleted successfully"}), 200

    except Exception as e:
        print("❌ Error deleting garden:", str(e))
        return jsonify({"error": str(e)}), 500

# route de mise à jour des données météo
@app.route('/update-weather-data', methods=['POST'])
def update_weather_data():
    try:
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return jsonify({"error": "Missing Authorization Header"}), 401

        token = auth_header.split(" ")[1]
        decoded_token = auth.verify_id_token(token)
        uid = decoded_token.get('uid')

        if not uid:
            return jsonify({"error": "Invalid token"}), 401

        data = request.json
        garden_id = data.get("gardenId")

        if not garden_id:
            return jsonify({"error": "Missing garden ID"}), 400

        garden_ref = db.collection("users").document(uid).collection("gardens").document(garden_id)
        garden_doc = garden_ref.get()

        if not garden_doc.exists:
            return jsonify({"error": "Garden not found"}), 404

        garden_data = garden_doc.to_dict()
        garden_type = garden_data.get("type")
        location = garden_data.get("location")
        start_date = garden_data.get("startDate")

        if garden_type != "outdoor":
            return jsonify({"error": "Weather data is only available for outdoor gardens"}), 400

        if not location:
            return jsonify({"error": "Missing location data (lat/lon required)"}), 400

        lat = location.get("lat")
        lon = location.get("lon")

        if not lat or not lon:
            return jsonify({"error": "Invalid location data (lat/lon required)"}), 400
    

        today = datetime.datetime.now(pytz.utc)

        # 🔥 Vérifier la dernière mise à jour
        weather_data_ref = garden_ref.collection("weather_data").document("last_update")
        last_update_doc = weather_data_ref.get()

        if last_update_doc.exists:
            last_update = last_update_doc.to_dict().get("lastUpdate")
        else:
            last_update = start_date
        
        # 🔥 Convertir last_update en datetime UTC-aware
        last_update_date = datetime.datetime.fromisoformat(last_update)
        if last_update_date.tzinfo is None:
            last_update_date = last_update_date.replace(tzinfo=pytz.utc)

        print(f"📌 Last update date: {last_update_date}")
        print(f"📌 Today date: {today}")

        if last_update_date >= today:
            return jsonify({"message": "Weather data is already up to date"}), 200

        # 🔥 Forcer les heures à des valeurs fixes : 00:00, 01:00, 02:00, ..., jusqu'à l'heure actuelle
        start_fetch = last_update_date.replace(minute=0, second=0, microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
        end_fetch = today.replace(minute=0, second=0, microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")

        # 🔥 Paramètres météo demandés
        params = "t_2m:C,relative_humidity_2m:p,msl_pressure:hPa,uv:idx,weather_symbol_1h:idx"
        weather_url = f"{METEOMATICS_BASE_URL}/{start_fetch}--{end_fetch}:PT1H/{params}/{lat},{lon}/json"

        try:
            response = requests.get(weather_url, auth=(METEOMATICS_USERNAME, METEOMATICS_PASSWORD))
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            print(f"❌ Error fetching weather data from Meteomatics: {str(e)}")
            return jsonify({"error": "Failed to fetch weather data from Meteomatics", "details": str(e)}), 500

        weather_data = response.json()
        print("🔍 Données Meteomatics brutes :", weather_data)

        # 🔥 Structurer les données par JOUR
        structured_data = {}

        for entry in weather_data.get("data", []):
            parameter = entry["parameter"]
            for coordinate in entry["coordinates"]:
                for date_entry in coordinate["dates"]:
                    full_date = datetime.datetime.fromisoformat(date_entry["date"][:-1])  # Convertir la date
                    full_date = full_date.replace(tzinfo=pytz.utc)  # Assurer UTC

                    date = full_date.strftime("%Y-%m-%d")  # YYYY-MM-DD
                    time = full_date.strftime("%H:%M")  # HH:MM

                    # 🔥 Ne garder que les entrées qui sont exactement à HH:00
                    if time[-2:] != "00":
                        continue  

                    value = date_entry["value"]

                    if date not in structured_data:
                        structured_data[date] = {"date": date, "data": []}

                    time_entry = next((d for d in structured_data[date]["data"] if d["time"] == time), None)
                    if not time_entry:
                        time_entry = {"time": time}
                        structured_data[date]["data"].append(time_entry)

                    # Associer la valeur au bon paramètre
                    if parameter == "t_2m:C":
                        time_entry["temperature"] = value
                    elif parameter == "relative_humidity_2m:p":
                        time_entry["humidity"] = value
                    elif parameter == "msl_pressure:hPa":
                        time_entry["pressure"] = value
                    elif parameter == "uv:idx":
                        time_entry["uv_index"] = value
                    elif parameter == "weather_symbol_1h:idx":
                        time_entry["weather_symbol"] = value

        print(f"📝 Données avant stockage :", structured_data)

        # 🔥 Stocker les données par JOUR dans Firestore
        for date, values in structured_data.items():
            weather_doc = garden_ref.collection("weather_data").document(date)

            # Récupérer les données existantes
            existing_doc = weather_doc.get()
            existing_data = existing_doc.to_dict().get("data", []) if existing_doc.exists else []

            # Fusionner les nouvelles entrées uniquement si elles ne sont pas déjà là
            existing_times = {entry["time"] for entry in existing_data}
            new_entries = [entry for entry in values["data"] if entry["time"] not in existing_times]

            if new_entries:
                print(f"✅ Ajout de {len(new_entries)} nouvelles entrées pour {date}")

                # Mise à jour complète avec merge=True
                updated_data = existing_data + new_entries
                weather_doc.set({"date": date, "data": updated_data}, merge=True)  
            else:
                print(f"⏳ Aucune nouvelle donnée à ajouter pour {date}, toutes les heures sont déjà enregistrées.")

        # 🔥 Mettre à jour la dernière date de mise à jour
        weather_data_ref.set({"lastUpdate": today.isoformat()})

        return jsonify({"message": "Weather data updated successfully"}), 200

    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"❌ Error updating weather data: {str(e)}")
        print(f"🔍 Stack Trace:\n{error_details}")
        return jsonify({"error": str(e), "traceback": error_details}), 500

#metéo en direct
@app.route('/live-weather', methods=['POST'])
def live_weather():
    try:
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return jsonify({"error": "Missing Authorization Header"}), 401

        token = auth_header.split(" ")[1]
        decoded_token = auth.verify_id_token(token)
        uid = decoded_token.get('uid')

        if not uid:
            return jsonify({"error": "Invalid token"}), 401

        data = request.json
        garden_id = data.get("gardenId")

        if not garden_id:
            return jsonify({"error": "Missing garden ID"}), 400

        garden_ref = db.collection("users").document(uid).collection("gardens").document(garden_id)
        garden_doc = garden_ref.get()

        if not garden_doc.exists:
            return jsonify({"error": "Garden not found"}), 404

        garden_data = garden_doc.to_dict()
        location = garden_data.get("location")

        # ✅ Nouveau contrôle basé sur latitude et longitude
        if not location or "lat" not in location or "lon" not in location:
            return jsonify({"error": "Live weather is only available for gardens with a valid location (lat/lon)."}), 400

        lat = location["lat"]
        lon = location["lon"]

        print(f"📌 Garden ID: {garden_id}, Lat: {lat}, Lon: {lon}")

        # 🔥 Paramètres météo demandés
        params = "t_2m:C,relative_humidity_2m:p,msl_pressure:hPa,uv:idx,weather_symbol_1h:idx"
        now = datetime.datetime.now(pytz.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        weather_url = f"{METEOMATICS_BASE_URL}/{now}/{params}/{lat},{lon}/json"

        try:
            response = requests.get(weather_url, auth=(METEOMATICS_USERNAME, METEOMATICS_PASSWORD))
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            print(f"❌ Error fetching live weather data: {str(e)}")
            return jsonify({"error": "Failed to fetch live weather data", "details": str(e)}), 500

        weather_data = response.json()

        # 🔥 Structurer la réponse
        live_weather_data = {}
        for entry in weather_data.get("data", []):
            parameter = entry["parameter"]
            value = entry["coordinates"][0]["dates"][0]["value"]

            if parameter == "t_2m:C":
                live_weather_data["temperature"] = value
            elif parameter == "relative_humidity_2m:p":
                live_weather_data["humidity"] = value
            elif parameter == "msl_pressure:hPa":
                live_weather_data["pressure"] = value
            elif parameter == "uv:idx":
                live_weather_data["uv_index"] = value
            elif parameter == "weather_symbol_1h:idx":
                live_weather_data["weather_symbol"] = value
            print(f"🌡️ Temperature: {live_weather_data.get('temperature')}°C")

        return jsonify(live_weather_data), 200

    except Exception as e:
        print(f"❌ Error fetching live weather data: {str(e)}")
        return jsonify({"error": str(e)}), 500
    

# ✅ 📌 Route de récupération des données météoo
@app.route('/get-weather-history', methods=['GET'])
def get_weather_history():
    try:
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return jsonify({"error": "Missing Authorization Header"}), 401

        token = auth_header.split(" ")[1]
        decoded_token = auth.verify_id_token(token)
        uid = decoded_token.get('uid')

        if not uid:
            return jsonify({"error": "Invalid token"}), 401

        garden_id = request.args.get("gardenId")

        if not garden_id:
            return jsonify({"error": "Missing garden ID"}), 400

        garden_ref = db.collection("users").document(uid).collection("gardens").document(garden_id)
        weather_ref = garden_ref.collection("weather_data")

        weather_docs = weather_ref.stream()

        weather_history = []
        for doc in weather_docs:
            data = doc.to_dict()
            if "data" in data:  # On s'assure que ce n'est pas "lastUpdate"
                weather_history.append(data)

        print(f"✅ Weather history retrieved for garden: {garden_id}")
        print(f"📊 Total entries: {len(weather_history)}")

        return jsonify(weather_history), 200

    except Exception as e:
        print(f"❌ Error fetching weather history: {str(e)}")
        return jsonify({"error": str(e)}), 500
    
# ✅ 📌 **Route pour récupérer les données en temps réel**
@app.route('/live-sensor-data', methods=['GET'])
def live_sensor_data():
    try:
        # 🔐 Vérifier le token Firebase
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return jsonify({"error": "Missing Authorization Header"}), 401

        token = auth_header.split(" ")[1]
        decoded_token = auth.verify_id_token(token)
        uid = decoded_token.get('uid')

        if not uid:
            return jsonify({"error": "Invalid token"}), 401

        # 🔥 Pas besoin de sensorId, car les données live sont globales par utilisateur
        sensor_ref = db.collection("test").document("Ua4bgGFb4ibdrZohzulN").collection("live").document("snapshot")
        sensor_doc = sensor_ref.get()

        if not sensor_doc.exists:
            return jsonify({"error": "No live data available"}), 404

        sensor_data = sensor_doc.to_dict()
        return jsonify(sensor_data), 200

    except Exception as e:
        print(f"❌ Error fetching live sensor data: {str(e)}")
        return jsonify({"error": str(e)}), 500


# ✅ 📌 **Route pour récupérer l'historique des capteurs**
@app.route('/get-sensor-history', methods=['GET'])
def get_sensor_history():
    try:
        # 🔐 Vérifier le token Firebase
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return jsonify({"error": "Missing Authorization Header"}), 401

        token = auth_header.split(" ")[1]
        decoded_token = auth.verify_id_token(token)
        uid = decoded_token.get('uid')

        if not uid:
            return jsonify({"error": "Invalid token"}), 401

        # 🔥 Récupération du sensor ID et de la date
        sensor_id = request.args.get("sensorId")
        date = request.args.get("date")  # Format attendu "YYYY-MM-DD"
        if not sensor_id or not date:
            return jsonify({"error": "Missing sensor ID or date"}), 400

        # 🔥 Construction du chemin Firestore
        history_ref = db.collection("test").document(uid).collection("dates").document(date).collection("hours")

        # 🔥 Récupérer toutes les heures enregistrées pour ce jour-là
        history_docs = history_ref.stream()

        history_data = {}
        for doc in history_docs:
            hour = doc.id
            history_data[hour] = doc.to_dict()

        return jsonify(history_data), 200

    except Exception as e:
        print(f"❌ Error fetching sensor history: {str(e)}")
        return jsonify({"error": str(e)}), 500

# ✅ 📌 Route d'accueil
@app.route("/", methods=["GET"])
def home():
    return jsonify({"message": "Welcome to CeresKeeper API!"}), 200

# ✅ Lancer le serveur
if __name__ == '__main__':
    app.run(debug=True)