from app.extensions import db
import datetime
import pytz

def create_garden_for_user(uid, name, start_date, garden_type, postal_code=None, location=None):
    garden_data = {
        "name": name,
        "startDate": start_date,
        "type": garden_type,
        "postalCode": postal_code,
        "location": location,
        "createdAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "userId": uid
    }

    garden_ref = db.collection("users").document(uid).collection("gardens").add(garden_data)
    garden_id = garden_ref[1].id

    # Créer les sous-collections par défaut
    db.collection("users").document(uid).collection("gardens").document(garden_id).collection("weather_data").add({
        "message": "Default weather folder created",
        "createdAt": datetime.datetime.now(datetime.timezone.utc).isoformat()
    })

    db.collection("users").document(uid).collection("gardens").document(garden_id).collection("sensors").add({
        "message": "Default sensor folder created",
        "createdAt": datetime.datetime.now(datetime.timezone.utc).isoformat()
    })

    return garden_id

def get_all_gardens_for_user(uid):
    user_ref = db.collection("users").document(uid).collection("gardens")
    gardens = user_ref.stream()
    results = []
    for garden in gardens:
        data = garden.to_dict()
        data['id'] = garden.id
        results.append(data)
    return results

def get_garden_by_id(uid, garden_id):
    garden_ref = db.collection("users").document(uid).collection("gardens").document(garden_id)
    garden_doc = garden_ref.get()
    return garden_doc.to_dict() if garden_doc.exists else None

def delete_garden_by_id(uid, garden_id):
    garden_ref = db.collection("users").document(uid).collection("gardens").document(garden_id)
    if not garden_ref.get().exists:
        return False

    # Supprimer sous-collections
    for sensor in garden_ref.collection("sensors").stream():
        garden_ref.collection("sensors").document(sensor.id).delete()

    for weather in garden_ref.collection("weather_data").stream():
        garden_ref.collection("weather_data").document(weather.id).delete()

    garden_ref.delete()
    return True