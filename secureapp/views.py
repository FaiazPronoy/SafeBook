# secureapp/views.py

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import get_user_model, login, logout
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, redirect, render

from keymgmt.services import create_key_envelope_for_user, get_user_dek

from .auth_utils import check_credentials
from .crypto import aead_decrypt, aead_encrypt
from .forms import LoginForm, RegisterForm
from .mac import row_mac
from .models import Message, Post
from .rsa_utils import (
    generate_rsa_keypair,
    load_private_key_from_der,
    load_public_key_from_pem,
    rsa_unwrap_session_key,
    rsa_wrap_session_key,
)

import os

Account = get_user_model()


# -------------------------
# Auth
# -------------------------

def register_view(request):
    if request.method == "POST":
        form = RegisterForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data["username"].strip()
            password = form.cleaned_data["password1"]
            email_plain = form.cleaned_data["email"].strip()
            phone_plain = form.cleaned_data["phone"].strip()

            user = Account.objects.create_user(username=username, password=password)
            try:
                # Per-user DEK envelope
                create_key_envelope_for_user(user)
                dek = get_user_dek(user)

                # Encrypt PII with user DEK
                email_nonce, email_ct = aead_encrypt(dek, email_plain.encode(), b"users.email")
                phone_nonce, phone_ct = aead_encrypt(dek, phone_plain.encode(), b"users.phone")
                user.email_ct, user.email_nonce = email_ct, email_nonce
                user.phone_ct, user.phone_nonce = phone_ct, phone_nonce

                # RSA keypair for messaging; private key wrapped with DEK
                pub_pem, priv_der = generate_rsa_keypair()
                user.public_key_pem = pub_pem.decode()
                priv_nonce, priv_ct = aead_encrypt(dek, priv_der, b"user.private_key")
                user.privkey_nonce = priv_nonce
                user.privkey_ct = priv_ct

                user.save()
            except Exception as e:
                user.delete()
                messages.error(request, f"Registration failed: {e}")
                return redirect("register")

            messages.success(request, "Registered. Please login.")
            return redirect("login")
    else:
        form = RegisterForm()
    return render(request, "register.html", {"form": form})

def login_view(request):
    if request.method == "POST":
        form = LoginForm(request.POST)
        if form.is_valid():
            user = check_credentials(
                form.cleaned_data["username"].strip(),
                form.cleaned_data["password"],
            )
            if user:
                login(request, user)
                next_url = request.GET.get("next") or request.POST.get("next")
                return redirect(next_url or "index")
            messages.error(request, "Invalid credentials.")
    else:
        form = LoginForm()
    return render(request, "registration/login.html", {"form": form})

def logout_view(request):
    logout(request)
    messages.info(request, "Logged out.")
    return redirect("login")


@login_required
def index_view(request):
    user = request.user
    dek = get_user_dek(user)

    email = aead_decrypt(dek, user.email_nonce, user.email_ct, b"users.email").decode() if user.email_ct else ""
    phone = aead_decrypt(dek, user.phone_nonce, user.phone_ct, b"users.phone").decode() if user.phone_ct else ""

    rows = Post.objects.filter(user=user).order_by("-created_at")
    posts = []
    for p in rows:
        try:
            title = aead_decrypt(dek, p.title_nonce, p.title_ct, b"posts.title").decode()
        except Exception:
            title = "[decrypt error]"
        posts.append({
            "id": p.id,
            "title": (title or "Untitled"),
            "created_at": p.created_at,
            "is_public": getattr(p, "is_public", False),
        })

    return render(request, "index.html", {"email": email, "phone": phone, "posts": posts})


@login_required
def feed_view(request):
    """Public feed: show other users’ public posts (decrypted server-side)."""
    posts = (
        Post.objects
        .filter(is_public=True)
        .exclude(user=request.user)
        .select_related("user")
        .order_by("-created_at")
    )

    items = []
    for p in posts:
        try:
            owner_dek = get_user_dek(p.user)
            title = aead_decrypt(owner_dek, p.title_nonce, p.title_ct, b"posts.title").decode()
            body = aead_decrypt(owner_dek, p.body_nonce, p.body_ct, b"posts.body").decode()
            payload = p.title_nonce + p.title_ct + p.body_nonce + p.body_ct
            mac_ok = (p.mac == row_mac(owner_dek, payload)) if p.mac else True
        except Exception:
            title, body, mac_ok = "[decrypt error]", "", False

        items.append({
            "id": p.id,
            "author": p.user.username,
            "title": title,
            "body": body,
            "created_at": p.created_at,
            "mac_ok": mac_ok,
        })

    return render(request, "feed.html", {"items": items})


@login_required
def post_new_view(request):
    if request.method == "POST":
        title = request.POST.get("title", "").strip()
        body = request.POST.get("body", "").strip()
        is_public = (request.POST.get("is_public") == "on")

        if not title or not body:
            messages.error(request, "Title and body are required.")
            return redirect("post_new")

        dek = get_user_dek(request.user)

        t_nonce, t_ct = aead_encrypt(dek, title.encode(), b"posts.title")
        b_nonce, b_ct = aead_encrypt(dek, body.encode(), b"posts.body")

        p = Post(
            user=request.user,
            title_ct=t_ct, title_nonce=t_nonce,
            body_ct=b_ct, body_nonce=b_nonce,
            is_public=is_public,
        )

        payload = t_nonce + t_ct + b_nonce + b_ct
        p.mac = row_mac(dek, payload)
        p.save()

        messages.success(request, "Post created.")
        return redirect("index")

    return render(request, "post_new.html")


@login_required
def post_detail_view(request, post_id: int):
    """Allow owner OR anyone if the post is_public."""
    p = get_object_or_404(Post, id=post_id)

    if not p.is_public and p.user_id != request.user.id:
        messages.error(request, "You do not have permission to view this post.")
        return redirect("index")

    owner_dek = get_user_dek(p.user)

    payload = p.title_nonce + p.title_ct + p.body_nonce + p.body_ct
    mac_ok = (p.mac == row_mac(owner_dek, payload)) if p.mac else True

    title = aead_decrypt(owner_dek, p.title_nonce, p.title_ct, b"posts.title").decode()
    body = aead_decrypt(owner_dek, p.body_nonce, p.body_ct, b"posts.body").decode()

    return render(request, "post_detail.html", {
        "post": p,
        "post_id": p.id,             # for {% url 'post_delete' post_id %}
        "title": title,
        "body": body,
        "mac_ok": mac_ok,
        "created_at": p.created_at,
        "author": p.user.username,
        "is_public": p.is_public,
    })


@login_required
def post_delete_view(request, post_id: int):
    post = get_object_or_404(Post, id=post_id, user=request.user)

    if request.method == "POST":
        post.delete()
        messages.success(request, "Post deleted.")
        return redirect("index")

    try:
        dek = get_user_dek(request.user)
        title = aead_decrypt(dek, post.title_nonce, post.title_ct, b"posts.title").decode()
    except Exception:
        title = "[decrypt error]"

    return render(request, "post_delete_confirm.html", {"post": post, "title": title})



@login_required
def messages_inbox_view(request):
    user = request.user
    qs = Message.objects.filter(recipient=user).select_related("sender").order_by("-created_at")

    inbox = []
    for m in qs:
        try:
            if m.is_asymmetric and m.rsa_wrapped_session_key:
                dek = get_user_dek(user)
                priv_der = aead_decrypt(dek, user.privkey_nonce, user.privkey_ct, b"user.private_key")
                priv = load_private_key_from_der(priv_der)

                session_key = rsa_unwrap_session_key(priv, m.rsa_wrapped_session_key)

                payload = m.rsa_wrapped_session_key + m.title_nonce + m.title_ct + m.body_nonce + m.body_ct
                mac_ok = (m.mac == row_mac(session_key, payload)) if m.mac else True

                title = aead_decrypt(session_key, m.title_nonce, m.title_ct, b"msg.title").decode()
    
        except Exception:
            title = "[decrypt error]"
            mac_ok = False

        inbox.append({
            "id": m.id,
            "title": title,
            "from": ("Anonymous" if m.is_anonymous or not m.sender else m.sender.username),
            "mac_ok": mac_ok,
            "created_at": m.created_at,
        })

    return render(request, "messages_inbox.html", {"inbox": inbox})


@login_required
def message_new_view(request):
    if request.method == "POST":
        to_username = request.POST.get("to", "").strip()
        title = request.POST.get("title", "").strip()
        body = request.POST.get("body", "").strip()
        anon = (request.POST.get("anonymous") == "on")

        if not (to_username and title and body):
            messages.error(request, "Recipient, title and body are required.")
            return redirect("message_new")

        try:
            recipient = Account.objects.get(username=to_username)
        except Account.DoesNotExist:
            messages.error(request, "Recipient not found.")
            return redirect("message_new")

        use_rsa = getattr(settings, "USE_RSA_MESSAGES", True) and bool(recipient.public_key_pem)

        if use_rsa:
            session_key = os.urandom(32)
            t_nonce, t_ct = aead_encrypt(session_key, title.encode(), b"msg.title")
            b_nonce, b_ct = aead_encrypt(session_key, body.encode(), b"msg.body")

            pub = load_public_key_from_pem(recipient.public_key_pem.encode())
            wrapped = rsa_wrap_session_key(pub, session_key)

            msg = Message(
                recipient=recipient,
                sender=None if anon else request.user,
                is_anonymous=anon,
                title_ct=t_ct, title_nonce=t_nonce,
                body_ct=b_ct, body_nonce=b_nonce,
                rsa_wrapped_session_key=wrapped,
                is_asymmetric=True,
            )
            payload = wrapped + t_nonce + t_ct + b_nonce + b_ct
            msg.mac = row_mac(session_key, payload)
            msg.save()
            messages.success(request, f"Message sent to {to_username}.")
            return redirect("messages_inbox")

    return render(request, "message_new.html")


@login_required
def message_detail_view(request, msg_id: int):
    m = get_object_or_404(Message, id=msg_id, recipient=request.user)
    user = request.user

    if m.is_asymmetric and m.rsa_wrapped_session_key:
        dek = get_user_dek(user)
        priv_der = aead_decrypt(dek, user.privkey_nonce, user.privkey_ct, b"user.private_key")
        priv = load_private_key_from_der(priv_der)

        session_key = rsa_unwrap_session_key(priv, m.rsa_wrapped_session_key)

        payload = m.rsa_wrapped_session_key + m.title_nonce + m.title_ct + m.body_nonce + m.body_ct
        mac_ok = (m.mac == row_mac(session_key, payload)) if m.mac else True

        title = aead_decrypt(session_key, m.title_nonce, m.title_ct, b"msg.title").decode()
        body = aead_decrypt(session_key, m.body_nonce, m.body_ct, b"msg.body").decode()

    sender_name = "Anonymous" if m.is_anonymous or not m.sender else m.sender.username
    return render(request, "message_detail.html", {
        "title": title,
        "body": body,
        "from": sender_name,
        "mac_ok": mac_ok,
        "created_at": m.created_at
    })
