from firebase_admin import storage
from PIL import Image
import io
import datetime

def resize_image(image_data, max_size=1024, quality=100):
    image = Image.open(io.BytesIO(image_data))

    if image.mode == 'RGBA':
        image = image.convert('RGB')

    image.thumbnail((max_size, max_size), Image.LANCZOS)

    img_byte_array = io.BytesIO()
    image.save(img_byte_array, format='JPEG', quality=quality)
    return img_byte_array.getvalue()

def upload_image_to_firebase(image_data, folder="plants"):
    filename = f"{folder}/plant_{datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d%H%M%S')}.jpg"
    bucket = storage.bucket()
    blob = bucket.blob(filename)
    blob.upload_from_string(image_data, content_type="image/jpeg")
    blob.make_public()
    return blob.public_url