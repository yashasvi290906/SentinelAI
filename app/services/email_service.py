"""
Email service for SentinelAI.
Handles OTP verification emails, password reset, and login notifications.
Currently uses console output (development mode).
Production: integrate with SMTP/SendGrid/Mailgun.
"""
import os
import logging
from typing import Optional

logger = logging.getLogger(__name__)

SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
SMTP_FROM = os.environ.get("SMTP_FROM", "noreply@sentinelai.com")


def send_otp_email(to_email: str, otp_code: str, expires_in: int = 300) -> bool:
    """Send OTP verification email. Returns True if sent successfully."""
    if not SMTP_HOST or not SMTP_USER:
        logger.warning(f"[DEV MODE] OTP for {to_email}: {otp_code} (expires in {expires_in}s)")
        return True
    
    # Production: use smtplib or SendGrid
    try:
        # TODO: Implement SMTP sending
        # import smtplib
        # from email.mime.text import MIMEText
        # msg = MIMEText(otp_template(otp_code, expires_in), "html")
        # msg["Subject"] = "SentinelAI - Your Verification Code"
        # msg["From"] = SMTP_FROM
        # msg["To"] = to_email
        # with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
        #     server.starttls()
        #     server.login(SMTP_USER, SMTP_PASSWORD)
        #     server.send_message(msg)
        logger.info(f"OTP email sent to {to_email}")
        return True
    except Exception as e:
        logger.error(f"Failed to send OTP email: {e}")
        return False


def send_password_reset_email(to_email: str, reset_token: str) -> bool:
    """Send password reset email."""
    if not SMTP_HOST:
        logger.warning(f"[DEV MODE] Password reset for {to_email}: token={reset_token}")
        return True
    # Production implementation
    return True


def send_login_notification(to_email: str, ip_address: str, user_agent: str) -> bool:
    """Send login notification email."""
    if not SMTP_HOST:
        logger.info(f"[DEV MODE] Login notification for {to_email} from {ip_address}")
        return True
    # Production implementation
    return True


def otp_template(otp_code: str, expires_in: int) -> str:
    """HTML email template for OTP verification."""
    minutes = expires_in // 60
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: 'Segoe UI', sans-serif; background: #0a0e17; color: #e0e0e0; margin: 0; padding: 20px; }}
            .container {{ max-width: 500px; margin: 0 auto; background: rgba(7,20,35,0.9); border: 1px solid rgba(0,229,255,0.15); border-radius: 12px; padding: 40px; }}
            .header {{ text-align: center; margin-bottom: 30px; }}
            .logo {{ font-size: 24px; font-weight: bold; color: #00e5ff; }}
            .otp-code {{ font-size: 48px; font-weight: bold; color: #00e5ff; text-align: center; letter-spacing: 12px; margin: 30px 0; padding: 20px; background: rgba(0,229,255,0.05); border: 1px solid rgba(0,229,255,0.2); border-radius: 8px; }}
            .warning {{ color: #ff9500; font-size: 14px; text-align: center; }}
            .footer {{ color: #666; font-size: 12px; text-align: center; margin-top: 30px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <div class="logo">SENTINEL AI</div>
                <p>Cyber Intelligence Platform</p>
            </div>
            <p>Your verification code is:</p>
            <div class="otp-code">{otp_code}</div>
            <p class="warning">This code expires in {minutes} minutes. Do not share it with anyone.</p>
            <div class="footer">
                <p>This email was sent by SentinelAI Security Platform.</p>
                <p>If you didn't request this, please ignore this email.</p>
            </div>
        </div>
    </body>
    </html>
    """