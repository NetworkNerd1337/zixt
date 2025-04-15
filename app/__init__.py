from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO
from flask_wtf.csrf import CSRFProtect
from .email import EmailService
import os
import redis

db = SQLAlchemy()
socketio = SocketIO()
csrf = CSRFProtect()
email_service = None
redis_client = None


def create_app():
    global email_service, redis_client
    app = Flask(__name__)
    app.config.from_object('config.Config')
    db.init_app(app)
    csrf.init_app(app)

    # Initialize Redis
    redis_client = redis.Redis(
        host=app.config['REDIS_HOST'],
        port=app.config['REDIS_PORT'],
        decode_responses=True
    )

    # Initialize SocketIO with Redis
    socketio.init_app(app, message_queue=f'redis://{app.config["REDIS_HOST"]}:{app.config["REDIS_PORT"]}')

    # Initialize email service
    email_service = EmailService(
        smtp_server=app.config['SMTP_SERVER'],
        smtp_port=app.config['SMTP_PORT'],
        sender_email=app.config['SENDER_EMAIL'],
        sender_password=app.config['SENDER_PASSWORD']
    )

    # Security headers
    @app.after_request
    def apply_security_headers(response):
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' https://cdnjs.cloudflare.com; "
            "style-src 'self'; "
            "img-src 'self' data:; "
            "connect-src 'self' ws://localhost:8000 wss://yourdomain.com"
        )
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        return response

    with app.app_context():
        from . import routes
        db.create_all()
    return app