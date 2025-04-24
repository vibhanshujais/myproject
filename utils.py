import random
from django.core.mail import send_mail
from django.conf import settings

def generate_otp():
    return ''.join([str(random.randint(0, 9)) for _ in range(6)])

def send_otp_email(email, otp):
    subject = 'E-Vault Login OTP'
    message = f'Your one-time password (OTP) for E-Vault login is: {otp}\nThis OTP is valid for 10 minutes.'
    send_mail(
        subject,
        message,
        settings.EMAIL_HOST_USER,
        [email],
        fail_silently=False,
    )

def send_verification_email(email, token):
    subject = 'E-Vault Email Verification'
    verification_url = f'http://localhost:8000/verify-email/{token}/'
    message = f'Please verify your email by clicking the link: {verification_url}\nThis link is valid for 24 hours.'
    send_mail(
        subject,
        message,
        settings.EMAIL_HOST_USER,
        [email],
        fail_silently=False,
    )