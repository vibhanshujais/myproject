import random
from django.core.mail import send_mail
from django.conf import settings

def generate_otp():
    return ''.join([str(random.randint(0, 9)) for _ in range(6)])

def send_otp_email(email, otp):
    subject = 'E-Vault Login OTP'
    message = f'Your one-time password (OTP) for E-Vault login is: {otp}\nThis OTP is valid for 10 minutes.'
    try:
        result = send_mail(
            subject,
            message,
            settings.EMAIL_HOST_USER,
            [email],
            fail_silently=False,
        )
        print(f"OTP email sent to {email}: {result}")
        return result
    except Exception as e:
        print(f"Failed to send OTP email to {email}: {str(e)}")
        raise

def send_verification_email(email, token):
    subject = 'E-Vault Email Verification'
    verification_url = f'http://localhost:8000/verify-email/{token}/'
    message = f'Please verify your email by clicking the link: {verification_url}\nThis link is valid for 24 hours.'
    try:
        send_mail(
            subject,
            message,
            settings.EMAIL_HOST_USER,
            [email],
            fail_silently=False,
        )
    except Exception as e:
        print(f"Failed to send verification email to {email}: {str(e)}")
        raise



def send_password_reset_email(email, token):
    subject = 'E-Vault Password Reset'
    reset_url = f'http://localhost:8000/reset-password/{token}/'
    message = f"""
    You have requested to reset your password for E-Vault.
    Please click the link below to set a new password:
    {reset_url}
    This link is valid for 1 hour.
    If you did not request a password reset, please ignore this email.
    """
    try:
        result = send_mail(
            subject,
            message,
            settings.EMAIL_HOST_USER,
            [email],
            fail_silently=False,
        )
        print(f"Password reset email sent to {email}: {result}")
        return result
    except Exception as e:
        print(f"Failed to send password reset email to {email}: {str(e)}")
        raise