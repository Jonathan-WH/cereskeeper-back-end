import os
import requests
from firebase_admin import auth
from app.extensions import db

FIREBASE_API_KEY = os.getenv("Firebase_API_KEY")

def email_exists_in_firebase(email):
    try:
        auth.get_user_by_email(email)
        return True
    except:
        return False

def username_exists_in_firestore(username):
    users = db.collection("users").where("username", "==", username).stream()
    return any(users)

def create_firebase_user(email, password, username):
    return auth.create_user(email=email, password=password, display_name=username)

def login_with_firebase(email, password):
    if not FIREBASE_API_KEY:
        print("❌ Firebase API Key missing")
        return None

    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={FIREBASE_API_KEY}"
    payload = {
        "email": email,
        "password": password,
        "returnSecureToken": True
    }

    response = requests.post(url, json=payload)
    if response.status_code != 200:
        return None
    return response.json()