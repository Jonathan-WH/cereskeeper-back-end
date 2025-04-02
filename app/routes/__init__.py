from .auth_routes import auth_bp
from .garden_routes import garden_bp
from .weather_routes import weather_bp
from .analysis_routes import analysis_bp
from .image_routes import image_bp
from .sensor_routes import sensor_bp

def register_routes(app):
    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(garden_bp, url_prefix="/garden")
    app.register_blueprint(weather_bp, url_prefix="/weather")
    app.register_blueprint(analysis_bp, url_prefix="/analysis")
    app.register_blueprint(image_bp, url_prefix="/image")
    app.register_blueprint(sensor_bp, url_prefix="/sensor")