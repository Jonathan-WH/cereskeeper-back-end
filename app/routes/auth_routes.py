from flask import Blueprint, request, jsonify
from app.extensions import db
import datetime
import os
import re

from app.services.firebase_service import verify_token
from app.services.auth_service import (
    email_exists_in_firebase,
    username_exists_in_firestore,
    create_firebase_user,
    login_with_firebase
)

auth_bp = Blueprint("auth", __name__)

FIREBASE_API_KEY = os.getenv("Firebase_API_KEY")


auth_bp = Blueprint("auth", __name__)

@auth_bp.route('/register', methods=['POST'])
def register():
    try:
        data = request.json
        email = data.get('email', '').strip()
        password = data.get('password', '').strip()
        username = data.get('username', '').strip()
        confirm_password = data.get('confirmPassword', '').strip()

        if not email or not password or not username:
            return jsonify({"error": "Missing required fields"}), 400

        if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):
            return jsonify({"error": "Invalid email format"}), 400

        if not re.match(r'^(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$', password):
            return jsonify({"error": "Password must be at least 8 characters, include one uppercase letter, one number, and one special character."}), 400

        if password != confirm_password:
            return jsonify({"error": "Passwords do not match"}), 400

        if len(username) < 8:
            return jsonify({"error": "Username must be at least 8 characters long"}), 400

        if email_exists_in_firebase(email):
            return jsonify({"error": "Email already exists"}), 400

        if username_exists_in_firestore(username):
            return jsonify({"error": "Username already exists"}), 400

        user = create_firebase_user(email, password, username)
        uid = user.uid

        # Création dans Firestore
        db.collection("users").document(uid).set({
            "uid": uid,
            "email": email,
            "username": username,
            "createdAt": datetime.datetime.now(datetime.timezone.utc).isoformat()
        })

        login_data = login_with_firebase(email, password)
        if not login_data:
            return jsonify({"error": "Account created but login failed"}), 500

        return jsonify({
            "message": "User registered successfully",
            "uid": uid,
            "idToken": login_data.get("idToken")
        }), 201

    except Exception as e:
        print("❌ Error in register:", str(e))
        return jsonify({"error": str(e)}), 500
    

@auth_bp.route('/login', methods=['POST'])
def login():
    try:
        data = request.json
        email = data.get('email', '').strip()
        password = data.get('password', '').strip()

        if not email or not password:
            return jsonify({"error": "Missing email or password"}), 400

        login_data = login_with_firebase(email, password)

        if not login_data:
            return jsonify({"error": "Invalid email or password"}), 401

        return jsonify({
            "message": "Login successful",
            "uid": login_data.get("localId"),
            "idToken": login_data.get("idToken")
        }), 200

    except Exception as e:
        print("❌ Error in login:", str(e))
        return jsonify({"error": str(e)}), 500


@auth_bp.route('/home-connected', methods=['GET'])
def home_connected():
    try:
        uid = verify_token(request.headers.get('Authorization'))

        user_ref = db.collection("users").document(uid)
        user_doc = user_ref.get()

        if not user_doc.exists:
            return jsonify({"error": "User not found"}), 404

        return jsonify({
            "message": "Welcome to home-connected",
            "user": user_doc.to_dict()
        }), 200

    except Exception as e:
        print("❌ Error in home-connected:", str(e))
        return jsonify({"error": str(e)}), 401