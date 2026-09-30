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

    # the profile is public on purpose: it is how friends find each other
    display_name = models.CharField(max_length=60, blank=True)
    bio = models.CharField(max_length=160, blank=True)

    @property
    def name(self) -> str:
        return self.display_name or self.username

    @property
    def initials(self) -> str:
        parts = self.name.split()
        return "".join(p[0] for p in parts[:2]).upper() or "?"

    @property
    def hue(self) -> int:
        """A colour for the avatar and cover that stays the same for a person."""
        return int(hashlib.md5(self.username.encode()).hexdigest()[:4], 16) % 360

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
    """A post. The text is encrypted under a key of its own.

    That key is always wrapped for the author. What else happens to it
    depends on who the post is for:

        only me   nothing else. Only the author's password opens it.
        friends   wrapped again for each friend, with that friend's RSA
                  public key, one PostShare row each. The server holds the
                  rows but has no private key to open any of them.
        public    wrapped under the server KEK, because a public post has
                  to render for people who are not signed in as anybody.

    Changing the audience adds or drops wrapped keys and never touches the
    ciphertext.
    """

    ONLY_ME, FRIENDS, PUBLIC = "me", "friends", "public"
    AUDIENCES = [(ONLY_ME, "Only me"), (FRIENDS, "Friends"), (PUBLIC, "Public")]

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    audience = models.CharField(max_length=10, choices=AUDIENCES, default=FRIENDS)

    key_owner = models.BinaryField()                      # post key, for the author
    key_public = models.BinaryField(null=True, blank=True)  # post key, for the server
    # which server KEK sealed key_public, so a rotation can find its own work
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
    """One friend's copy of one post key, locked with that friend's public key."""

    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name="shares")
    reader = models.ForeignKey(Account, on_delete=models.CASCADE, related_name="shared_with_me")
    wrapped_key = models.BinaryField()

    class Meta:
        constraints = [models.UniqueConstraint(fields=["post", "reader"], name="one_share_per_reader")]


class Comment(models.Model):
    """Encrypted with the key of the post it sits under, so exactly the people
    who can read the post can read what was said about it."""

    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name="comments")
    author = models.ForeignKey(Account, on_delete=models.CASCADE)
    body_ct = models.BinaryField()
    body_nonce = models.BinaryField()
    mac = models.BinaryField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["created_at"]


class Like(models.Model):
    """Not encrypted. Who liked what is metadata, and the page says so."""

    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name="likes")
    user = models.ForeignKey(Account, on_delete=models.CASCADE)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["post", "user"], name="one_like_each")]


class FriendRequest(models.Model):
    """A request, and once accepted, the friendship itself."""

    from_user = models.ForeignKey(Account, on_delete=models.CASCADE, related_name="requests_sent")
    to_user = models.ForeignKey(Account, on_delete=models.CASCADE, related_name="requests_received")
    created_at = models.DateTimeField(auto_now_add=True)
    accepted_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["from_user", "to_user"], name="one_request_each_way")]


class Message(models.Model):
    """One chat message.

    A fresh session key encrypts the text; the recipient's RSA public key
    wraps the session key, and the sender's public key wraps a second copy
    so the sender can scroll back through the chat. The server holds both
    and can open neither.
    """

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
