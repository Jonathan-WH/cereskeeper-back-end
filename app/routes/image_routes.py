from flask import Blueprint, request, jsonify
from app.services.image_service import resize_image, upload_image_to_firebase

image_bp = Blueprint("image", __name__)

@image_bp.route('/upload-image', methods=['POST'])
def upload_image():
    try:
        if 'image' not in request.files:
            return jsonify({"error": "No image provided"}), 400

        image_file = request.files['image']
        image_data = image_file.read()

        resized = resize_image(image_data)
        image_url = upload_image_to_firebase(resized)

        return jsonify({"image_url": image_url}), 200

    except Exception as e:
        print("❌ Error uploading image:", str(e))
        return jsonify({"error": str(e)}), 500