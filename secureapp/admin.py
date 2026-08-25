from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import Account, Post, Message

# ---- small helpers ----
def _hex_preview(b, n=12):
    if not b:
        return ", "
    try:
        return bytes(b)[:n].hex() + "…"
    except Exception:
        return ", "

def _hex_full(b):
    if not b:
        return ", "
    try:
        return bytes(b).hex()
    except Exception:
        return ", "


# -------------------------
# Message admin
# -------------------------
@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "recipient",
        "sender",
        "is_anonymous",
        "is_asymmetric",
        "created_at",
        "title_preview",
        "body_preview",
    )
    search_fields = ("recipient__username", "sender__username")
    list_filter = ("is_anonymous", "is_asymmetric", "created_at")
    date_hierarchy = "created_at"
    ordering = ("-created_at",)

    # Show FULL ciphertext on the detail page
    readonly_fields = (
        "title_ct_hex",
        "title_nonce_hex",
        "body_ct_hex",
        "body_nonce_hex",
        "mac_hex",
        "rsa_wrapped_session_key_hex",
    )

    fieldsets = (
        (None, {
            "fields": ("recipient", "sender", "is_anonymous", "is_asymmetric", "created_at")
        }),
        ("Encrypted Title", {
            "fields": ("title_ct_hex", "title_nonce_hex")
        }),
        ("Encrypted Body", {
            "fields": ("body_ct_hex", "body_nonce_hex")
        }),
        ("Integrity / Asymmetric", {
            "fields": ("mac_hex", "rsa_wrapped_session_key_hex")
        }),
    )

    # list_display previews
    @admin.display(description="Title (cipher preview)")
    def title_preview(self, obj):
        return _hex_preview(obj.title_ct)

    @admin.display(description="Body (cipher preview)")
    def body_preview(self, obj):
        return _hex_preview(obj.body_ct)

    # detail-view full hex
    @admin.display(description="title_ct (hex)")
    def title_ct_hex(self, obj):
        return _hex_full(obj.title_ct)

    @admin.display(description="title_nonce (hex)")
    def title_nonce_hex(self, obj):
        return _hex_full(obj.title_nonce)

    @admin.display(description="body_ct (hex)")
    def body_ct_hex(self, obj):
        return _hex_full(obj.body_ct)

    @admin.display(description="body_nonce (hex)")
    def body_nonce_hex(self, obj):
        return _hex_full(obj.body_nonce)

    @admin.display(description="mac (hex)")
    def mac_hex(self, obj):
        return _hex_full(obj.mac)

    @admin.display(description="rsa_wrapped_session_key (hex)")
    def rsa_wrapped_session_key_hex(self, obj):
        return _hex_full(obj.rsa_wrapped_session_key)


# -------------------------
# Post admin
# -------------------------
@admin.register(Post)
class PostAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "user",
        "is_public",
        "created_at",
        "title_preview",
        "body_preview",
    )
    search_fields = ("user__username",)
    list_filter = ("is_public", "created_at")
    date_hierarchy = "created_at"
    ordering = ("-created_at",)

    readonly_fields = (
        "title_ct_hex",
        "title_nonce_hex",
        "body_ct_hex",
        "body_nonce_hex",
        "mac_hex",
    )

    fieldsets = (
        (None, {"fields": ("user", "is_public", "created_at")}),
        ("Encrypted Title", {"fields": ("title_ct_hex", "title_nonce_hex")}),
        ("Encrypted Body", {"fields": ("body_ct_hex", "body_nonce_hex")}),
        ("Integrity", {"fields": ("mac_hex",)}),
    )

    @admin.display(description="Title (cipher preview)")
    def title_preview(self, obj):
        return _hex_preview(obj.title_ct)

    @admin.display(description="Body (cipher preview)")
    def body_preview(self, obj):
        return _hex_preview(obj.body_ct)

    @admin.display(description="title_ct (hex)")
    def title_ct_hex(self, obj):
        return _hex_full(obj.title_ct)

    @admin.display(description="title_nonce (hex)")
    def title_nonce_hex(self, obj):
        return _hex_full(obj.title_nonce)

    @admin.display(description="body_ct (hex)")
    def body_ct_hex(self, obj):
        return _hex_full(obj.body_ct)

    @admin.display(description="body_nonce (hex)")
    def body_nonce_hex(self, obj):
        return _hex_full(obj.body_nonce)

    @admin.display(description="mac (hex)")
    def mac_hex(self, obj):
        return _hex_full(obj.mac)


# -------------------------
# Account admin
# -------------------------
@admin.register(Account)
class AccountAdmin(UserAdmin):
    # keep the standard UserAdmin columns; add short previews in list
    list_display = (
        "username",
        "email_preview",     # encrypted email preview
        "phone_preview",     # encrypted phone preview
        "is_active",
        "is_staff",
        "date_joined",
    )
    search_fields = ("username", "email")  # email is plaintext field on AbstractUser
    list_filter = ("is_active", "is_staff", "is_superuser", "date_joined")
    ordering = ("-date_joined",)

    # show full ciphertexts in detail page
    readonly_fields = (
        "wrapped_dek_hex",
        "email_ct_hex",
        "email_nonce_hex",
        "phone_ct_hex",
        "phone_nonce_hex",
        "privkey_ct_hex",
        "privkey_nonce_hex",
    )

    fieldsets = UserAdmin.fieldsets + (
        ("Crypto (DEK wrapping)", {
            "fields": ("wrapped_dek_hex", "dek_kek_version"),
        }),
        ("Encrypted PII", {
            "fields": ("email_ct_hex", "email_nonce_hex", "phone_ct_hex", "phone_nonce_hex"),
        }),
        ("Private Key (encrypted)", {
            "fields": ("public_key_pem", "privkey_ct_hex", "privkey_nonce_hex"),
        }),
    )

    # list_display previews for encrypted PII
    @admin.display(description="Email (cipher preview)")
    def email_preview(self, obj):
        return _hex_preview(obj.email_ct)

    @admin.display(description="Phone (cipher preview)")
    def phone_preview(self, obj):
        return _hex_preview(obj.phone_ct)

    # detail-view full hex
    @admin.display(description="wrapped_dek (hex)")
    def wrapped_dek_hex(self, obj):
        return _hex_full(obj.wrapped_dek)

    @admin.display(description="email_ct (hex)")
    def email_ct_hex(self, obj):
        return _hex_full(obj.email_ct)

    @admin.display(description="email_nonce (hex)")
    def email_nonce_hex(self, obj):
        return _hex_full(obj.email_nonce)

    @admin.display(description="phone_ct (hex)")
    def phone_ct_hex(self, obj):
        return _hex_full(obj.phone_ct)

    @admin.display(description="phone_nonce (hex)")
    def phone_nonce_hex(self, obj):
        return _hex_full(obj.phone_nonce)

    @admin.display(description="privkey_ct (hex)")
    def privkey_ct_hex(self, obj):
        return _hex_full(obj.privkey_ct)

    @admin.display(description="privkey_nonce (hex)")
    def privkey_nonce_hex(self, obj):
        return _hex_full(obj.privkey_nonce)





""" from django.contrib import admin
from .models import Account, Post
from django.contrib.auth.admin import UserAdmin
from .models import Message
from django.contrib import admin
from .models import Message

@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "recipient",
        "sender",
        "is_anonymous",
        "is_asymmetric",
        "created_at",
        "title_preview",
        "body_preview",
    )
    search_fields = ("recipient__username", "sender__username")

    @admin.display(description="Title")
    def title_preview(self, obj):
        if obj.title_ct:
            return obj.title_ct[:12].hex() + "…"  # first 12 bytes of ciphertext
        return ", "

    @admin.display(description="Body")
    def body_preview(self, obj):
        if obj.body_ct:
            return obj.body_ct[:12].hex() + "…"
        return ", "

@admin.register(Account)
class AccountAdmin(UserAdmin):
    fieldsets = UserAdmin.fieldsets + (
        ("Crypto", {"fields": ("wrapped_dek","dek_kek_version","email_ct","email_nonce","phone_ct","phone_nonce")}),
    )

@admin.register(Post)
class PostAdmin(admin.ModelAdmin):
    list_display = ("id","user","created_at")
 """