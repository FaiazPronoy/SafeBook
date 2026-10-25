from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.utils.html import format_html

from .models import Account, Comment, FriendRequest, LoginAttempt, Message, Post, PostShare


def _hex(value, limit=None):
    if not value:
        return "none"
    raw = bytes(value)
    text = raw.hex()
    if limit and len(raw) > limit:
        return f"{raw[:limit].hex()}… ({len(raw)} bytes)"
    return f"{text} ({len(raw)} bytes)"


def _mono(value, limit=None):
    return format_html('<code style="word-break:break-all">{}</code>', _hex(value, limit))


class CipherColumn:
    @staticmethod
    def make(field, label, limit=None):
        def show(self, obj):
            return _mono(getattr(obj, field), limit)
        show.short_description = label
        return show


@admin.register(Account)
class AccountAdmin(UserAdmin):
    list_display = ("username", "is_staff", "has_envelope", "has_recovery", "fingerprint_short")
    search_fields = ("username",)
    readonly_fields = ("pdek_wrapped_hex", "rec_wrapped_hex", "email_hex", "phone_hex",
                       "privkey_hex", "key_fingerprint", "rec_used_at")

    fieldsets = UserAdmin.fieldsets + (
        ("Key envelopes", {"fields": ("pdek_wrapped_hex", "rec_wrapped_hex", "rec_used_at")}),
        ("Encrypted profile", {"fields": ("email_hex", "phone_hex")}),
        ("Messaging identity", {"fields": ("key_fingerprint", "public_key_pem", "privkey_hex")}),
    )

    @admin.display(boolean=True, description="Password envelope")
    def has_envelope(self, obj):
        return bool(obj.pdek_wrapped)

    @admin.display(boolean=True, description="Recovery envelope")
    def has_recovery(self, obj):
        return bool(obj.rec_wrapped)

    @admin.display(description="Key fingerprint")
    def fingerprint_short(self, obj):
        return obj.key_fingerprint[:19] or "none"

    pdek_wrapped_hex = CipherColumn.make("pdek_wrapped", "Private DEK, wrapped by the password")
    rec_wrapped_hex = CipherColumn.make("rec_wrapped", "Private DEK, wrapped by the recovery code")
    email_hex = CipherColumn.make("email_ct", "Email (ciphertext)")
    phone_hex = CipherColumn.make("phone_ct", "Phone (ciphertext)")
    privkey_hex = CipherColumn.make("privkey_ct", "RSA private key (ciphertext)", limit=48)


@admin.register(Post)
class PostAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "audience", "created_at", "body_preview")
    list_filter = ("audience", "created_at")
    search_fields = ("user__username",)
    date_hierarchy = "created_at"
    readonly_fields = ("key_owner_hex", "key_public_hex", "body_hex", "mac_hex")

    fieldsets = (
        (None, {"fields": ("user", "audience", "created_at")}),
        ("Content key, wrapped", {"fields": ("key_owner_hex", "key_public_hex")}),
        ("Ciphertext", {"fields": ("body_hex", "mac_hex")}),
    )

    @admin.display(description="Body (ciphertext)")
    def body_preview(self, obj):
        return _hex(obj.body_ct, limit=10)

    key_owner_hex = CipherColumn.make("key_owner", "Wrapped for the author")
    key_public_hex = CipherColumn.make("key_public", "Wrapped for the server (public posts only)")
    body_hex = CipherColumn.make("body_ct", "Body", limit=64)
    mac_hex = CipherColumn.make("mac", "Row MAC")


@admin.register(PostShare)
class PostShareAdmin(admin.ModelAdmin):
    list_display = ("post", "reader", "key_preview")
    search_fields = ("reader__username",)

    @admin.display(description="Post key, RSA-OAEP for the reader")
    def key_preview(self, obj):
        return _hex(obj.wrapped_key, limit=12)


@admin.register(Comment)
class CommentAdmin(admin.ModelAdmin):
    list_display = ("id", "post", "author", "created_at", "body_preview")

    @admin.display(description="Body (ciphertext)")
    def body_preview(self, obj):
        return _hex(obj.body_ct, limit=10)


@admin.register(FriendRequest)
class FriendRequestAdmin(admin.ModelAdmin):
    list_display = ("from_user", "to_user", "created_at", "accepted_at")
    list_filter = ("accepted_at",)


@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
    list_display = ("id", "sender", "recipient", "created_at", "body_preview")
    search_fields = ("recipient__username", "sender__username")
    date_hierarchy = "created_at"
    readonly_fields = ("key_recipient_hex", "key_sender_hex", "body_hex", "mac_hex")

    fieldsets = (
        (None, {"fields": ("sender", "recipient", "read_at", "created_at")}),
        ("Session key, wrapped with RSA-OAEP", {"fields": ("key_recipient_hex", "key_sender_hex")}),
        ("Ciphertext", {"fields": ("body_hex", "mac_hex")}),
    )

    @admin.display(description="Body (ciphertext)")
    def body_preview(self, obj):
        return _hex(obj.body_ct, limit=10)

    key_recipient_hex = CipherColumn.make("key_for_recipient", "For the recipient", limit=48)
    key_sender_hex = CipherColumn.make("key_for_sender", "For the sender", limit=48)
    body_hex = CipherColumn.make("body_ct", "Body", limit=64)
    mac_hex = CipherColumn.make("mac", "Row MAC")


@admin.register(LoginAttempt)
class LoginAttemptAdmin(admin.ModelAdmin):
    list_display = ("at", "username", "successful", "ip", "user_agent")
    list_filter = ("successful", "at")
    search_fields = ("username", "ip")
    date_hierarchy = "at"

    def has_add_permission(self, request):
        return False
