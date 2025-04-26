from django.contrib.auth.models import AbstractUser
from django.db import models

class CustomUser(AbstractUser):
    USER_TYPE_CHOICES = (
        ('client', 'Client'),
        ('court', 'Court'),
        ('lawyer', 'Lawyer'),
    )
    user_type = models.CharField(max_length=10, choices=USER_TYPE_CHOICES)
    phone = models.CharField(max_length=15, blank=True)
    is_email_verified = models.BooleanField(default=False)


    def __str__(self):
        return self.username

""" class Document(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    file = models.FileField(upload_to='documents/')
    uploaded_at = models.DateTimeField(auto_now_add=True)
    title = models.CharField(max_length=100) """

class Document(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    file = models.FileField(upload_to='documents/')
    cid = models.CharField(max_length=100, blank=True)
    filename = models.CharField(max_length=255,blank=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    title = models.CharField(max_length=100)
    category = models.CharField(
        max_length=50,
        choices=(
            ('contract', 'Contract'),
            ('evidence', 'Evidence'),
            ('motion', 'Motion'),
            ('other', 'Other'),
        ),
        default='other'
    )
    def __str__(self):
        return self.filename