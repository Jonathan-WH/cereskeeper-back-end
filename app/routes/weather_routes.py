from flask import Blueprint, request, jsonify
from app.services.firebase_service import verify_token
from app.services.weather_service import (
    fetch_live_weather_for_garden,
    fetch_weather_history_for_garden,
    update_weather_data_for_garden
)


weather_bp = Blueprint("weather", __name__)

@weather_bp.route('/live', methods=['POST'])
def live_weather():
    try:
        uid = verify_token(request.headers.get("Authorization"))
        data = request.json
        garden_id = data.get("gardenId")
        if not garden_id:
            return jsonify({"error": "Missing garden ID"}), 400

        weather = fetch_live_weather_for_garden(uid, garden_id)
        return jsonify(weather), 200

    except Exception as e:
        print("❌ Error fetching live weather data:", str(e))
        return jsonify({"error": str(e)}), 500

# #metéo en direct avec meteomatics
# @app.route('/live-weather', methods=['POST'])
# def live_weather():
#     try:
#         auth_header = request.headers.get("Authorization")
#         if not auth_header:
#             return jsonify({"error": "Missing Authorization Header"}), 401

#         token = auth_header.split(" ")[1]
#         decoded_token = auth.verify_id_token(token)
#         uid = decoded_token.get('uid')

#         if not uid:
#             return jsonify({"error": "Invalid token"}), 401

#         data = request.json
#         garden_id = data.get("gardenId")

#         if not garden_id:
#             return jsonify({"error": "Missing garden ID"}), 400

#         garden_ref = db.collection("users").document(uid).collection("gardens").document(garden_id)
#         garden_doc = garden_ref.get()

#         if not garden_doc.exists:
#             return jsonify({"error": "Garden not found"}), 404

#         garden_data = garden_doc.to_dict()
#         location = garden_data.get("location")

#         # ✅ Nouveau contrôle basé sur latitude et longitude
#         if not location or "lat" not in location or "lon" not in location:
#             return jsonify({"error": "Live weather is only available for gardens with a valid location (lat/lon)."}), 400

#         lat = location["lat"]
#         lon = location["lon"]

#         print(f"📌 Garden ID: {garden_id}, Lat: {lat}, Lon: {lon}")

#         # 🔥 Paramètres météo demandés
#         params = "t_2m:C,relative_humidity_2m:p,msl_pressure:hPa,uv:idx,weather_symbol_1h:idx"
#         now = datetime.datetime.now(pytz.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
#         weather_url = f"{METEOMATICS_BASE_URL}/{now}/{params}/{lat},{lon}/json"

#         try:
#             response = requests.get(weather_url, auth=(METEOMATICS_USERNAME, METEOMATICS_PASSWORD))
#             response.raise_for_status()
#         except requests.exceptions.RequestException as e:
#             print(f"❌ Error fetching live weather data: {str(e)}")
#             return jsonify({"error": "Failed to fetch live weather data", "details": str(e)}), 500

#         weather_data = response.json()

#         # 🔥 Structurer la réponse
#         live_weather_data = {}
#         for entry in weather_data.get("data", []):
#             parameter = entry["parameter"]
#             value = entry["coordinates"][0]["dates"][0]["value"]

#             if parameter == "t_2m:C":
#                 live_weather_data["temperature"] = value
#             elif parameter == "relative_humidity_2m:p":
#                 live_weather_data["humidity"] = value
#             elif parameter == "msl_pressure:hPa":
#                 live_weather_data["pressure"] = value
#             elif parameter == "uv:idx":
#                 live_weather_data["uv_index"] = value
#             elif parameter == "weather_symbol_1h:idx":
#                 live_weather_data["weather_symbol"] = value
#             print(f"🌡️ Temperature: {live_weather_data.get('temperature')}°C")

#         return jsonify(live_weather_data), 200

#     except Exception as e:
#         print(f"❌ Error fetching live weather data: {str(e)}")
#         return jsonify({"error": str(e)}), 500

@weather_bp.route('/history', methods=['GET'])
def get_weather_history():
    try:
        uid = verify_token(request.headers.get("Authorization"))
        garden_id = request.args.get("gardenId")
        if not garden_id:
            return jsonify({"error": "Missing garden ID"}), 400

        history = fetch_weather_history_for_garden(uid, garden_id)
        return jsonify(history), 200

    except Exception as e:
        print("❌ Error fetching weather history:", str(e))
        return jsonify({"error": str(e)}), 500
    

@weather_bp.route('/update', methods=['POST'])
def update_weather_data():
    try:
        uid = verify_token(request.headers.get("Authorization"))
        data = request.json
        garden_id = data.get("gardenId")
        if not garden_id:
            return jsonify({"error": "Missing garden ID"}), 400

        result = update_weather_data_for_garden(uid, garden_id)
        return jsonify(result), 200

    except Exception as e:
        print("❌ Error updating weather data:", str(e))
        return jsonify({"error": str(e)}), 500
