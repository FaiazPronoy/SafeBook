import hashlib

from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.db import models


class Account(AbstractUser):
    """A user, plus the envelopes that hold their keys.

    `username` and the Argon2 password hash are the only fields here that a
    database thief can read. Everything else is ciphertext.
    """

    # The private DEK, wrapped by a scrypt key derived from the password.
    # There is no copy of this key anywhere else, which is the point.
    pdek_salt = models.BinaryField(null=True, blank=True)
    pdek_wrapped = models.BinaryField(null=True, blank=True)

    # The same DEK, wrapped again by a scrypt key from the one time recovery
    # code shown at registration. Without this, a forgotten password means
    # the account's data is gone for good.
    rec_salt = models.BinaryField(null=True, blank=True)
    rec_wrapped = models.BinaryField(null=True, blank=True)
    rec_used_at = models.DateTimeField(null=True, blank=True)

    # PII, encrypted with the private DEK
    email_ct = models.BinaryField(null=True, blank=True)
    email_nonce = models.BinaryField(null=True, blank=True)
    phone_ct = models.BinaryField(null=True, blank=True)
    phone_nonce = models.BinaryField(null=True, blank=True)

    # Messaging identity. The public half is public; the private half is
    # encrypted with the private DEK like everything else.
    public_key_pem = models.TextField(blank=True)
    privkey_ct = models.BinaryField(null=True, blank=True)
    privkey_nonce = models.BinaryField(null=True, blank=True)

    @property
    def key_fingerprint(self) -> str:
        """SHA-256 of the public key, grouped for reading aloud.

        Two people compare this over a channel that is not SafeBook. If the
        server ever swapped one of their public keys for its own, the two
        strings stop matching.
        """
        if not self.public_key_pem:
            return ""
        digest = hashlib.sha256(self.public_key_pem.encode()).hexdigest().upper()
        return " ".join(digest[i:i + 4] for i in range(0, 32, 4))


class Post(models.Model):
    """A note. The body is encrypted under a key of its own.

    That key is wrapped for the author, and wrapped a second time for the
    server when the post is public. Flipping visibility adds or drops one
    wrapped key and never touches the ciphertext.
    """

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)

    key_owner = models.BinaryField()                      # post key, for the author
    key_public = models.BinaryField(null=True, blank=True)  # post key, for the feed
    # which server KEK sealed key_public, so a rotation can find its own work
    key_public_kek_id = models.IntegerField(null=True, blank=True)

    title_ct = models.BinaryField()
    title_nonce = models.BinaryField()
    body_ct = models.BinaryField()
    body_nonce = models.BinaryField()
    mac = models.BinaryField(null=True, blank=True)

    is_public = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"Post {self.id} by {self.user}"


class Message(models.Model):
    """One message, sealed for one recipient.

    A fresh session key encrypts the text; the recipient's RSA public key
    wraps the session key. The sender keeps a second copy of that session
    key wrapped under their own public key, so the outbox is readable
    without the server holding anything extra.
    """

    recipient = models.ForeignKey(Account, on_delete=models.CASCADE, related_name="inbox")
    sender = models.ForeignKey(Account, null=True, blank=True,
                               on_delete=models.SET_NULL, related_name="sent_messages")
    is_anonymous = models.BooleanField(default=False)

    title_ct = models.BinaryField()
    title_nonce = models.BinaryField()
    body_ct = models.BinaryField()
    body_nonce = models.BinaryField()
    mac = models.BinaryField(null=True, blank=True)

    key_for_recipient = models.BinaryField()
    key_for_sender = models.BinaryField(null=True, blank=True)

    read_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]


class LoginAttempt(models.Model):
    """Every attempt, right or wrong.

    Two jobs: the throttle counts recent failures for a username, and the
    account page shows the owner where their account has been signed into
    from. A failed attempt records the username as typed, because an account
    that does not exist is exactly what someone probing for accounts types.
    """

    username = models.CharField(max_length=150, db_index=True)
    successful = models.BooleanField(default=False)
    ip = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=200, blank=True)
    at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["-at"]
