from app.extensions import db

def get_live_sensor_snapshot():
    # 🔥 Donnée live brute (pour tests initiaux)
    sensor_ref = db.collection("test").document("Ua4bgGFb4ibdrZohzulN").collection("live").document("snapshot")
    sensor_doc = sensor_ref.get()
    return sensor_doc.to_dict() if sensor_doc.exists else None

def get_sensor_history_for_date(uid, date):
    # 🔥 Historique stocké par heure (document par heure)
    history_ref = db.collection("test").document(uid).collection("dates").document(date).collection("hours")
    history_docs = history_ref.stream()

    history_data = {}
    for doc in history_docs:
        hour = doc.id
        history_data[hour] = doc.to_dict()

    return history_data