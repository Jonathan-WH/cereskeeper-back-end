from firebase_admin import auth
from flask import jsonify

def extract_token(authorization_header):
    """Récupère le token depuis l’en-tête Authorization"""
    if not authorization_header:
        raise ValueError("Missing Authorization Header")

    if not authorization_header.startswith("Bearer "):
        raise ValueError("Invalid Authorization format. Expected Bearer token.")

    return authorization_header.split(" ")[1]

def decode_token(auth_header):
    """Décode un token Firebase et retourne le UID"""
    try:
        token = extract_token(auth_header)
        decoded = auth.verify_id_token(token)
        return decoded.get("uid")
    except Exception as e:
        raise ValueError("Invalid Firebase token")