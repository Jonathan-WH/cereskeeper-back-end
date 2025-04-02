from flask import Blueprint, request, jsonify
from app.services.firebase_service import verify_token
from app.services.garden_service import (
    create_garden_for_user,
    get_all_gardens_for_user,
    get_garden_by_id,
    delete_garden_by_id
)

garden_bp = Blueprint("garden", __name__)

@garden_bp.route('/create', methods=['POST'])
def create_garden():
    try:
        uid = verify_token(request.headers.get("Authorization"))
        data = request.json
        name = data.get('name')
        start_date = data.get('startDate')
        garden_type = data.get('type')
        postal_code = data.get('postalCode', None)
        location = data.get('location', None)

        if not name or not start_date or not garden_type:
            return jsonify({"error": "Missing required fields"}), 400

        garden_id = create_garden_for_user(uid, name, start_date, garden_type, postal_code, location)
        return jsonify({"message": "Garden created successfully", "gardenId": garden_id}), 201

    except Exception as e:
        print("❌ Error creating garden:", str(e))
        return jsonify({"error": str(e)}), 500


@garden_bp.route('/get-all', methods=['GET'])
def get_user_gardens():
    try:
        uid = verify_token(request.headers.get("Authorization"))
        gardens = get_all_gardens_for_user(uid)
        return jsonify(gardens), 200

    except Exception as e:
        print("❌ Error fetching gardens:", str(e))
        return jsonify({"error": str(e)}), 500

@garden_bp.route('/get', methods=['GET'])
def get_garden():
    try:
        uid = verify_token(request.headers.get("Authorization"))
        garden_id = request.args.get('id')
        if not garden_id:
            return jsonify({"error": "Missing garden ID"}), 400

        garden_data = get_garden_by_id(uid, garden_id)
        if not garden_data:
            return jsonify({"error": "Garden not found"}), 404

        return jsonify(garden_data), 200

    except Exception as e:
        print("❌ Error fetching garden details:", str(e))
        return jsonify({"error": str(e)}), 500

@garden_bp.route('/delete', methods=['DELETE'])
def delete_garden():
    try:
        uid = verify_token(request.headers.get("Authorization"))
        garden_id = request.args.get('gardenId')
        if not garden_id:
            return jsonify({"error": "Missing garden ID"}), 400

        success = delete_garden_by_id(uid, garden_id)
        if not success:
            return jsonify({"error": "Garden not found"}), 404

        return jsonify({"message": "Garden and associated sensors deleted successfully"}), 200

    except Exception as e:
        print("❌ Error deleting garden:", str(e))
        return jsonify({"error": str(e)}), 500