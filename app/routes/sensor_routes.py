from flask import Blueprint, request, jsonify
from app.services.firebase_service import verify_token
from app.services.sensor_service import (
    get_live_sensor_snapshot,
    get_sensor_history_for_date
)

sensor_bp = Blueprint("sensor", __name__)

@sensor_bp.route('/live', methods=['GET'])
def live_sensor_data():
    try:
        uid = verify_token(request.headers.get("Authorization"))
        data = get_live_sensor_snapshot()

        if not data:
            return jsonify({"error": "No live data available"}), 404

        return jsonify(data), 200

    except Exception as e:
        print(f"❌ Error fetching live sensor data: {str(e)}")
        return jsonify({"error": str(e)}), 500
    

@sensor_bp.route('/history', methods=['GET'])
def get_sensor_history():
    try:
        uid = verify_token(request.headers.get("Authorization"))
        sensor_id = request.args.get("sensorId")
        date = request.args.get("date")  # Format : YYYY-MM-DD

        if not sensor_id or not date:
            return jsonify({"error": "Missing sensor ID or date"}), 400

        data = get_sensor_history_for_date(uid, date)
        return jsonify(data), 200

    except Exception as e:
        print(f"❌ Error fetching sensor history: {str(e)}")
        return jsonify({"error": str(e)}), 500
    

