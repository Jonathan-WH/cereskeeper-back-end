from flask import Blueprint, request, jsonify
from firebase_admin import auth
from app.extensions import db
import datetime
from firebase_admin import storage
import os

from app.services.gpt_service import analyze_plant_gpt
from app.services.firebase_service import verify_token

analysis_bp = Blueprint("analysis", __name__)

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")


analysis_bp = Blueprint("analysis", __name__)

@analysis_bp.route('/analyze-plant', methods=['POST'])
def analyze_plant():
    try:
        data = request.json
        image_urls = data.get('image_urls', [])
        environment = data.get('environment', 'Not specified')
        variety = data.get('variety', 'Unknown')
        symptoms = data.get('symptoms', 'No symptoms reported')
        user_id = data.get('user_id')

        if not image_urls:
            return jsonify({"error": "No image URLs provided"}), 400

        # 🧠 Analyse via GPT service
        analysis_text = analyze_plant_gpt(image_urls, environment, variety, symptoms)

        analysis_data = {
            "title": "🌿 Plant Analysis Report",
            "date": datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),
            "images": image_urls,
            "problem_found": "✅ A problem was detected" if "problem" in analysis_text.lower() else "❌ No major issues detected",
            "analysis": analysis_text
        }

        db.collection("users").document(user_id).collection("analysis").add(analysis_data)

        return jsonify(analysis_data), 200

    except Exception as e:
        print("❌ Unexpected error in analyze_plant:", str(e))
        return jsonify({"error": str(e)}), 500
    

@analysis_bp.route('/get-analysis-history', methods=['GET'])
def get_analysis_history():
    try:
        uid = verify_token(request.headers.get("Authorization"))

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
    


@analysis_bp.route('/delete-analysis', methods=['DELETE'])
def delete_analysis():
    try:
        analysis_id = request.args.get('analysisId')
        uid = request.args.get('uid')

        if not analysis_id or not uid:
            return jsonify({"error": "Missing parameters"}), 400

        analysis_ref = db.collection("users").document(uid).collection("analysis").document(analysis_id)
        analysis_doc = analysis_ref.get()

        if not analysis_doc.exists:
            return jsonify({"error": "Analysis not found"}), 404

        analysis_data = analysis_doc.to_dict()
        image_urls = analysis_data.get("images", [])

        bucket = storage.bucket()
        for image_url in image_urls:
            path = "/".join(image_url.split('/')[-2:])
            blob = bucket.blob(path)
            if blob.exists():
                blob.delete()
                print(f"✅ Image deleted: {path}")
            else:
                print(f"⚠️ Image not found: {path}")

        analysis_ref.delete()

        return jsonify({"message": "Analysis and associated images deleted successfully"}), 200

    except Exception as e:
        print("❌ Error deleting analysis:", str(e))
        return jsonify({"error": str(e)}), 500