import hashlib

from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.db import models


class Account(AbstractUser):
    pdek_salt = models.BinaryField(null=True, blank=True)
    pdek_wrapped = models.BinaryField(null=True, blank=True)

    rec_salt = models.BinaryField(null=True, blank=True)
    rec_wrapped = models.BinaryField(null=True, blank=True)
    rec_used_at = models.DateTimeField(null=True, blank=True)

    email_ct = models.BinaryField(null=True, blank=True)
    email_nonce = models.BinaryField(null=True, blank=True)
    phone_ct = models.BinaryField(null=True, blank=True)
    phone_nonce = models.BinaryField(null=True, blank=True)

    public_key_pem = models.TextField(blank=True)
    privkey_ct = models.BinaryField(null=True, blank=True)
    privkey_nonce = models.BinaryField(null=True, blank=True)

    display_name = models.CharField(max_length=60, blank=True)
    bio = models.CharField(max_length=160, blank=True)

    two_step = models.BooleanField(default=False)

    @property
    def name(self) -> str:
        return self.display_name or self.username

    @property
    def initials(self) -> str:
        parts = self.name.split()
        return "".join(p[0] for p in parts[:2]).upper() or "?"

    @property
    def hue(self) -> int:
        return int(hashlib.md5(self.username.encode()).hexdigest()[:4], 16) % 360

    @property
    def key_fingerprint(self) -> str:
        if not self.public_key_pem:
            return ""
        digest = hashlib.sha256(self.public_key_pem.encode()).hexdigest().upper()
        return " ".join(digest[i:i + 4] for i in range(0, 32, 4))


class Post(models.Model):
    ONLY_ME, FRIENDS, PUBLIC = "me", "friends", "public"
    AUDIENCES = [(ONLY_ME, "Only me"), (FRIENDS, "Friends"), (PUBLIC, "Public")]

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    audience = models.CharField(max_length=10, choices=AUDIENCES, default=FRIENDS)

    key_owner = models.BinaryField()
    key_public = models.BinaryField(null=True, blank=True)
    key_public_kek_id = models.IntegerField(null=True, blank=True)

    body_ct = models.BinaryField()
    body_nonce = models.BinaryField()
    mac = models.BinaryField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    edited_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"Post {self.id} by {self.user}"

    @property
    def is_public(self):
        return self.audience == self.PUBLIC


class PostShare(models.Model):
    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name="shares")
    reader = models.ForeignKey(Account, on_delete=models.CASCADE, related_name="shared_with_me")
    wrapped_key = models.BinaryField()

    class Meta:
        constraints = [models.UniqueConstraint(fields=["post", "reader"], name="one_share_per_reader")]


class Comment(models.Model):
    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name="comments")
    author = models.ForeignKey(Account, on_delete=models.CASCADE)
    body_ct = models.BinaryField()
    body_nonce = models.BinaryField()
    mac = models.BinaryField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["created_at"]


class Like(models.Model):
    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name="likes")
    user = models.ForeignKey(Account, on_delete=models.CASCADE)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["post", "user"], name="one_like_each")]


class FriendRequest(models.Model):
    from_user = models.ForeignKey(Account, on_delete=models.CASCADE, related_name="requests_sent")
    to_user = models.ForeignKey(Account, on_delete=models.CASCADE, related_name="requests_received")
    created_at = models.DateTimeField(auto_now_add=True)
    accepted_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["from_user", "to_user"], name="one_request_each_way")]


class Message(models.Model):
    recipient = models.ForeignKey(Account, on_delete=models.CASCADE, related_name="inbox")
    sender = models.ForeignKey(Account, on_delete=models.CASCADE, related_name="sent_messages")

    body_ct = models.BinaryField()
    body_nonce = models.BinaryField()
    mac = models.BinaryField(null=True, blank=True)

    key_for_recipient = models.BinaryField()
    key_for_sender = models.BinaryField()

    read_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["created_at"]


class LoginAttempt(models.Model):
    username = models.CharField(max_length=150, db_index=True)
    successful = models.BooleanField(default=False)
    ip = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=200, blank=True)
    at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["-at"]
