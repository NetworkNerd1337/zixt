class Config:
    SECRET_KEY = os.urandom(32)
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://zixt_user:secure_password@localhost/zixt_db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SMTP_SERVER = 'smtp.gmail.com'
    SMTP_PORT = 465
    SENDER_EMAIL = 'your_email@gmail.com'
    SENDER_PASSWORD = 'your_app_password'
    REDIS_HOST = 'localhost'
    REDIS_PORT = 6379
    UPLOAD_FOLDER = 'app/uploads'
    WTF_CSRF_ENABLED = True
    WTF_CSRF_SECRET_KEY = os.urandom(32)