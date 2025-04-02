from app.utils.firebase_utils import decode_token

def verify_token(auth_header):
    """Vérifie et retourne l’UID Firebase"""
    return decode_token(auth_header)