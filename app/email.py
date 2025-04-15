import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import url_for
import hashlib
import os


class EmailService:
    def __init__(self, smtp_server, smtp_port, sender_email, sender_password):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.sender_email = sender_email
        self.sender_password = sender_password

    def generate_verification_token(self, email):
        return hashlib.sha3_256((email + os.urandom(16).hex()).encode()).hexdigest()

    def send_verification_email(self, recipient_email, username, token):
        verification_url = url_for('main.verify_email', token=token, _external=True)

        msg = MIMEMultipart()
        msg['From'] = self.sender_email
        msg['To'] = recipient_email
        msg['Subject'] = 'Zixt Email Verification'

        html = f"""
        <html>
            <body>
                <h2>Welcome to Zixt, {username}!</h2>
                <p>Please verify your email by clicking the link below:</p>
                <a href="{verification_url}">Verify Email</a>
                <p>If you didn't register, ignore this email.</p>
            </body>
        </html>
        """
        msg.attach(MIMEText(html, 'html'))

        try:
            with smtplib.SMTP_SSL(self.smtp_server, self.smtp_port) as server:
                server.login(self.sender_email, self.sender_password)
                server.sendmail(self.sender_email, recipient_email, msg.as_string())
            return True
        except Exception as e:
            print(f"Email sending failed: {e}")
            return False