"""
Email service for SentinelAI.
Sends OTP verification, password reset, and login notification emails via Gmail SMTP.
"""
import os
import smtplib
import ssl
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional

logger = logging.getLogger(__name__)

SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
SMTP_FROM = os.environ.get("SMTP_FROM", SMTP_USER)


def _send_email(to_email: str, subject: str, html_body: str) -> bool:
    """Send an HTML email via Gmail SMTP. Returns True on success."""
    if not SMTP_USER or not SMTP_PASSWORD:
        logger.warning("SMTP not configured — email to %s not sent", to_email)
        return False

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = SMTP_FROM or SMTP_USER
        msg["To"] = to_email
        msg.attach(MIMEText(html_body, "html"))

        context = ssl.create_default_context()
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
            server.ehlo()
            server.starttls(context=context)
            server.ehlo()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_FROM or SMTP_USER, to_email, msg.as_string())

        logger.info("Email sent to %s: %s", to_email, subject)
        return True
    except smtplib.SMTPAuthenticationError:
        logger.error("SMTP authentication failed — check SMTP_USER and SMTP_PASSWORD")
        return False
    except Exception as e:
        logger.error("Failed to send email to %s: %s", to_email, e)
        return False


def send_otp_email(to_email: str, otp_code: str, expires_in: int = 300) -> bool:
    """Send OTP verification email."""
    minutes = expires_in // 60
    html = f"""
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
    return _send_email(to_email, "SentinelAI — Your Verification Code", html)


def send_password_reset_email(to_email: str, reset_token: str) -> bool:
    """Send password reset email."""
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: 'Segoe UI', sans-serif; background: #0a0e17; color: #e0e0e0; margin: 0; padding: 20px; }}
            .container {{ max-width: 500px; margin: 0 auto; background: rgba(7,20,35,0.9); border: 1px solid rgba(0,229,255,0.15); border-radius: 12px; padding: 40px; }}
            .header {{ text-align: center; margin-bottom: 30px; }}
            .logo {{ font-size: 24px; font-weight: bold; color: #00e5ff; }}
            .token {{ font-size: 16px; color: #00e5ff; text-align: center; word-break: break-all; margin: 20px 0; padding: 15px; background: rgba(0,229,255,0.05); border: 1px solid rgba(0,229,255,0.2); border-radius: 8px; font-family: monospace; }}
            .warning {{ color: #ff9500; font-size: 14px; text-align: center; }}
            .footer {{ color: #666; font-size: 12px; text-align: center; margin-top: 30px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <div class="logo">SENTINEL AI</div>
                <p>Password Reset Request</p>
            </div>
            <p>You requested a password reset. Use the token below:</p>
            <div class="token">{reset_token}</div>
            <p class="warning">This token expires in 15 minutes. If you didn't request this, ignore this email.</p>
            <div class="footer">
                <p>SentinelAI Security Platform</p>
            </div>
        </div>
    </body>
    </html>
    """
    return _send_email(to_email, "SentinelAI — Password Reset", html)


def send_login_notification(to_email: str, ip_address: str, user_agent: str) -> bool:
    """Send login notification email."""
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: 'Segoe UI', sans-serif; background: #0a0e17; color: #e0e0e0; margin: 0; padding: 20px; }}
            .container {{ max-width: 500px; margin: 0 auto; background: rgba(7,20,35,0.9); border: 1px solid rgba(0,229,255,0.15); border-radius: 12px; padding: 40px; }}
            .header {{ text-align: center; margin-bottom: 30px; }}
            .logo {{ font-size: 24px; font-weight: bold; color: #00e5ff; }}
            .detail {{ font-size: 14px; color: #aaa; margin: 8px 0; }}
            .label {{ color: #00e5ff; }}
            .footer {{ color: #666; font-size: 12px; text-align: center; margin-top: 30px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <div class="logo">SENTINEL AI</div>
                <p>New Login Detected</p>
            </div>
            <p class="detail"><span class="label">IP Address:</span> {ip_address}</p>
            <p class="detail"><span class="label">Device:</span> {user_agent[:100]}</p>
            <p class="detail"><span class="label">Time:</span> {__import__('datetime').datetime.now(__import__('datetime').timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</p>
            <div class="footer">
                <p>If this wasn't you, change your password immediately.</p>
                <p>SentinelAI Security Platform</p>
            </div>
        </div>
    </body>
    </html>
    """
    return _send_email(to_email, "SentinelAI — New Login Detected", html)
