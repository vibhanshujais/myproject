from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone
from datetime import timedelta
import uuid

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
    

def default_expires_at():
    """Return the default expiration date (7 days from now)."""
    return timezone.now() + timedelta(days=7)

class SharedDocument(models.Model):
    """Model to track document sharing between users."""
    document = models.ForeignKey(
        Document,
        on_delete=models.CASCADE,
        help_text="The document being shared."
    )
    owner = models.ForeignKey(
        CustomUser,
        on_delete=models.CASCADE,
        related_name='shared_by',
        help_text="The user who owns the document."
    )
    recipient = models.ForeignKey(
        CustomUser,
        on_delete=models.CASCADE,
        related_name='shared_with',
        help_text="The user with whom the document is shared."
    )
    shared_at = models.DateTimeField(
        auto_now_add=True,
        help_text="The date and time when the document was shared."
    )
    token = models.UUIDField(
        default=uuid.uuid4,
        editable=False,
        unique=True,
        help_text="Unique token for accessing the shared document."
    )
    expires_at = models.DateTimeField(
        default=default_expires_at,
        help_text="Expiration date for the shared document link."
    )

    def __str__(self):
        return f"{self.document.filename} shared by {self.owner.username} with {self.recipient.username}"

    class Meta:
        verbose_name = "Shared Document"
        verbose_name_plural = "Shared Documents"
        unique_together = ['document', 'owner', 'recipient']
