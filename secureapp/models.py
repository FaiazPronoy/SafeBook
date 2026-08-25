from django.db import models
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.conf import settings

class Account(AbstractUser):
    # Per-user Data Encryption Key (DEK), wrapped by server KEK
    
    wrapped_dek = models.BinaryField(null=True, blank=True)
    dek_kek_version = models.IntegerField(default=1)

    # Encrypted PII (email/phone) using user's DEK (AES-GCM)
    email_ct = models.BinaryField(null=True, blank=True)
    email_nonce = models.BinaryField(null=True, blank=True)
    phone_ct = models.BinaryField(null=True, blank=True)
    phone_nonce = models.BinaryField(null=True, blank=True)
    public_key_pem = models.TextField(blank=True)                 # SubjectPublicKeyInfo PEM
    privkey_ct = models.BinaryField(null=True, blank=True)        # private key encrypted w/ user's DEK (AES-GCM)
    privkey_nonce = models.BinaryField(null=True, blank=True)

    # NOTE: `username` remains plaintext for login. Password is hashed+salted by Django.

class Post(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    # encrypted fields
    title_ct = models.BinaryField()
    title_nonce = models.BinaryField()
    body_ct = models.BinaryField()
    body_nonce = models.BinaryField()
    mac = models.BinaryField(null=True, blank=True)

    # NEW: visibility
    is_public = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Post {self.id} by {self.user}"


# --- MESSAGES ---
class Message(models.Model):
    # who receives (their DEK is used to encrypt content)
    recipient = models.ForeignKey(Account, on_delete=models.CASCADE, related_name="inbox")

    # optional sender (null -> anonymous)
    sender = models.ForeignKey(Account, null=True, blank=True, on_delete=models.SET_NULL, related_name="sent_messages")
    is_anonymous = models.BooleanField(default=False)

    # encrypted fields (AES-GCM with recipient DEK)
    title_ct = models.BinaryField()
    title_nonce = models.BinaryField()
    body_ct = models.BinaryField()
    body_nonce = models.BinaryField()

    # optional MAC over ciphertext tuple
    mac = models.BinaryField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
    
    rsa_wrapped_session_key = models.BinaryField(null=True, blank=True)  # RSA-OAEP(cipher(session_key))
    is_asymmetric = models.BooleanField(default=False)


