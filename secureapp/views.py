"""Every view that touches user data needs the private DEK, and the private
DEK only exists while someone is logged in. There is no path through this
file where the server reads a private post or a message on its own.
"""

import functools

from django.contrib import messages as flash
from django.contrib.auth import get_user_model, login as django_login, logout as django_logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import check_password
from django.db import transaction
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST

from keymgmt.services import get_active_kek

from . import keys
from .auth_utils import (MAX_FAILURES, check_credentials, clear_failures,
                         is_locked_out, record_attempt, recent_failures)
from .crypto import aead_decrypt, aead_encrypt, new_key
from .forms import (ChangePasswordForm, LoginForm, MessageForm, PostForm,
                    RecoverForm, RegisterForm)
from .mac import CTX_MESSAGE, CTX_POST, mac_ok, row_mac
from .models import LoginAttempt, Message, Post
from .recovery import new_recovery_code, normalise
from .rsa_utils import (generate_rsa_keypair, load_private_key_from_der,
                        load_public_key_from_pem, rsa_unwrap_session_key,
                        rsa_wrap_session_key)
from .session_keys import arm_session, disarm_session, read_private_dek

Account = get_user_model()

AAD_EMAIL = b"account.email"
AAD_PHONE = b"account.phone"
AAD_PRIVKEY = b"account.private_key"
AAD_POST_TITLE = b"post.title"
AAD_POST_BODY = b"post.body"
AAD_MSG_TITLE = b"message.title"
AAD_MSG_BODY = b"message.body"


# ---------------------------------------------------------------- plumbing

def needs_key(view):
    """Hand the view the private DEK, or send the user back to the login page.

    The DEK goes missing for ordinary reasons - the cookie half expired, the
    server restarted, the session was opened before a password change - and
    none of them are worth an error page.
    """
    @functools.wraps(view)
    @login_required
    def wrapper(request, *args, **kwargs):
        dek = read_private_dek(request)
        if dek is None:
            flash.info(request, "Please sign in again to unlock your data.")
            return redirect("login")
        return view(request, dek, *args, **kwargs)
    return wrapper


def _decrypt_post(post, post_key):
    """Title, body, and whether the row still hangs together."""
    intact = mac_ok(post.mac, post_key, CTX_POST,
                    str(post.user_id).encode(), post.title_nonce, post.title_ct,
                    post.body_nonce, post.body_ct)
    if not intact:
        return None, None, False
    title = aead_decrypt(post_key, post.title_nonce, post.title_ct, AAD_POST_TITLE).decode()
    body = aead_decrypt(post_key, post.body_nonce, post.body_ct, AAD_POST_BODY).decode()
    return title, body, True


def _seal_post(post, post_key, title, body, owner_id):
    post.title_nonce, post.title_ct = aead_encrypt(post_key, title.encode(), AAD_POST_TITLE)
    post.body_nonce, post.body_ct = aead_encrypt(post_key, body.encode(), AAD_POST_BODY)
    post.mac = row_mac(post_key, CTX_POST, str(owner_id).encode(),
                       post.title_nonce, post.title_ct, post.body_nonce, post.body_ct)


def _open_private_key(user, dek):
    der = aead_decrypt(dek, user.privkey_nonce, user.privkey_ct, AAD_PRIVKEY)
    return load_private_key_from_der(der)


def _message_row(message, session_key):
    intact = mac_ok(message.mac, session_key, CTX_MESSAGE,
                    str(message.recipient_id).encode(),
                    message.title_nonce, message.title_ct,
                    message.body_nonce, message.body_ct)
    if not intact:
        return None, None, False
    title = aead_decrypt(session_key, message.title_nonce, message.title_ct, AAD_MSG_TITLE).decode()
    body = aead_decrypt(session_key, message.body_nonce, message.body_ct, AAD_MSG_BODY).decode()
    return title, body, True


# ---------------------------------------------------------------- auth

def register_view(request):
    if request.user.is_authenticated:
        return redirect("index")

    form = RegisterForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        password = form.cleaned_data["password1"]
        code = new_recovery_code()

        with transaction.atomic():
            user = Account.objects.create_user(
                username=form.cleaned_data["username"], password=password
            )
            dek = new_key()

            # the same key, sealed twice: once by the password, once by the
            # code the user is about to be shown
            user.pdek_salt, user.pdek_wrapped = keys.seal_private_dek(dek, password)
            user.rec_salt, user.rec_wrapped = keys.seal_recovery_dek(dek, normalise(code))

            user.email_nonce, user.email_ct = aead_encrypt(
                dek, form.cleaned_data["email"].encode(), AAD_EMAIL)
            user.phone_nonce, user.phone_ct = aead_encrypt(
                dek, form.cleaned_data["phone"].strip().encode(), AAD_PHONE)

            pub_pem, priv_der = generate_rsa_keypair()
            user.public_key_pem = pub_pem.decode()
            user.privkey_nonce, user.privkey_ct = aead_encrypt(dek, priv_der, AAD_PRIVKEY)
            user.save()

        # shown once, on the next page, and never stored in a readable form
        request.session["fresh_recovery_code"] = code
        request.session["fresh_recovery_user"] = user.username
        return redirect("recovery_code")

    return render(request, "register.html", {"form": form})


def recovery_code_view(request):
    code = request.session.pop("fresh_recovery_code", None)
    username = request.session.pop("fresh_recovery_user", None)
    if not code:
        return redirect("login")
    return render(request, "recovery_code.html", {"code": code, "username": username})


def login_view(request):
    if request.user.is_authenticated:
        return redirect("index")

    form = LoginForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        username = form.cleaned_data["username"].strip()
        password = form.cleaned_data["password"]

        if is_locked_out(username):
            flash.error(request, "Too many failed attempts. Try again in 15 minutes.")
            return render(request, "registration/login.html", {"form": form})

        user = check_credentials(username, password)
        if user is None:
            record_attempt(request, username, False)
            left = MAX_FAILURES - recent_failures(username)
            # the same sentence whether the account exists or not
            flash.error(request, "Wrong username or password."
                                 + (f" {left} attempts left." if left <= 2 else ""))
            return render(request, "registration/login.html", {"form": form})

        try:
            dek = keys.open_private_dek(user.pdek_wrapped, user.pdek_salt, password)
        except Exception:
            # the password matched the hash but the envelope did not open, so
            # the two are out of step with each other
            record_attempt(request, username, False)
            flash.error(request, "Your key envelope could not be opened. "
                                 "Use your recovery code to set a new password.")
            return redirect("recover")

        record_attempt(request, username, True)
        clear_failures(username)
        django_login(request, user)                 # this rotates the session key
        response = redirect(request.POST.get("next") or "index")
        arm_session(request, response, dek)         # so it has to happen after
        return response

    return render(request, "registration/login.html", {"form": form})


@require_POST
def logout_view(request):
    """POST only, so a link on another site cannot sign someone out."""
    django_logout(request)
    response = redirect("login")
    disarm_session(request, response)
    flash.info(request, "Signed out. Your keys are no longer on this server.")
    return response


def recover_view(request):
    """Open the account with the recovery code and re-seal it under a new
    password. The DEK itself never changes, so nothing is re-encrypted."""
    form = RecoverForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        username = form.cleaned_data["username"].strip()
        user = Account.objects.filter(username__iexact=username).first()
        code = normalise(form.cleaned_data["code"])

        dek = None
        if user is not None and user.rec_wrapped:
            try:
                dek = keys.open_recovery_dek(user.rec_wrapped, user.rec_salt, code)
            except Exception:
                dek = None

        if dek is None:
            record_attempt(request, username, False)
            flash.error(request, "That username and recovery code do not match.")
            return render(request, "recover.html", {"form": form})

        new_password = form.cleaned_data["new1"]
        fresh_code = new_recovery_code()
        with transaction.atomic():
            user.set_password(new_password)
            user.pdek_salt, user.pdek_wrapped = keys.seal_private_dek(dek, new_password)
            # the used code is spent; issue a new one in the same breath
            user.rec_salt, user.rec_wrapped = keys.seal_recovery_dek(dek, normalise(fresh_code))
            user.rec_used_at = timezone.now()
            user.save()
        clear_failures(user.username)

        request.session["fresh_recovery_code"] = fresh_code
        request.session["fresh_recovery_user"] = user.username
        return redirect("recovery_code")

    return render(request, "recover.html", {"form": form})


# ---------------------------------------------------------------- account

@needs_key
def account_view(request, dek):
    user = request.user
    email = aead_decrypt(dek, user.email_nonce, user.email_ct, AAD_EMAIL).decode() if user.email_ct else ""
    phone = aead_decrypt(dek, user.phone_nonce, user.phone_ct, AAD_PHONE).decode() if user.phone_ct else ""

    return render(request, "account.html", {
        "email": email,
        "phone": phone,
        "fingerprint": user.key_fingerprint,
        "attempts": LoginAttempt.objects.filter(username=user.username)[:12],
        "form": ChangePasswordForm(),
        "kek_id": get_active_kek()[1],
        "envelope_hex": bytes(user.pdek_wrapped).hex() if user.pdek_wrapped else "",
        "envelope_len": len(bytes(user.pdek_wrapped)) if user.pdek_wrapped else 0,
        "public_posts": Post.objects.filter(user=user, is_public=True).count(),
        "private_posts": Post.objects.filter(user=user, is_public=False).count(),
    })


@needs_key
@require_POST
def change_password_view(request, dek):
    form = ChangePasswordForm(request.POST)
    if not form.is_valid():
        for error in form.errors.values():
            flash.error(request, error[0])
        return redirect("account")

    user = request.user
    if not check_password(form.cleaned_data["current"], user.password):
        flash.error(request, "That is not your current password.")
        return redirect("account")

    new_password = form.cleaned_data["new1"]
    with transaction.atomic():
        user.set_password(new_password)
        # only the envelope is rewritten. Not one post is touched.
        user.pdek_salt, user.pdek_wrapped = keys.seal_private_dek(dek, new_password)
        user.save()

    django_login(request, user)
    response = redirect("account")
    arm_session(request, response, dek)
    flash.success(request, "Password changed. Your posts were not re-encrypted - "
                           "only the envelope holding your key was.")
    return response


# ---------------------------------------------------------------- posts

@needs_key
def index_view(request, dek):
    user = request.user
    rows = Post.objects.filter(user=user)

    posts, unreadable = [], 0
    for post in rows:
        try:
            post_key = keys.unwrap_post_key_for_owner(post.key_owner, dek)
            title, _, intact = _decrypt_post(post, post_key)
        except Exception:
            title, intact = None, False
        if not intact:
            unreadable += 1
        posts.append({"id": post.id, "title": title or "could not be verified",
                      "intact": intact, "is_public": post.is_public,
                      "created_at": post.created_at})

    return render(request, "index.html", {
        "posts": posts,
        "unreadable": unreadable,
        "unread": Message.objects.filter(recipient=user, read_at__isnull=True).count(),
        "public_count": sum(1 for p in posts if p["is_public"]),
        "private_count": sum(1 for p in posts if not p["is_public"]),
        "sent_count": Message.objects.filter(sender=user).count(),
        "fingerprint": user.key_fingerprint,
    })


@login_required
def feed_view(request):
    """Public posts only. The server unwraps these with its own KEK, because
    a public post is meant to be readable by people who are not its author."""
    rows = Post.objects.filter(is_public=True).select_related("user")

    items = []
    for post in rows:
        try:
            post_key = keys.unwrap_post_key_for_public(post.key_public)
            title, body, intact = _decrypt_post(post, post_key)
        except Exception:
            intact = False
        if not intact:
            continue        # a row that does not verify is not shown at all
        items.append({"id": post.id, "author": post.user.username, "title": title,
                      "body": body, "created_at": post.created_at,
                      "mine": post.user_id == request.user.id})

    return render(request, "feed.html", {"items": items})


@needs_key
def post_new_view(request, dek):
    form = PostForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        is_public = form.cleaned_data["is_public"]
        post_key = keys.new_post_key()

        post = Post(user=request.user, is_public=is_public)
        post.key_owner = keys.wrap_post_key_for_owner(post_key, dek)
        if is_public:
            post.key_public = keys.wrap_post_key_for_public(post_key)
            post.key_public_kek_id = get_active_kek()[1]
        _seal_post(post, post_key, form.cleaned_data["title"],
                   form.cleaned_data["body"], request.user.id)
        post.save()

        flash.success(request, "Encrypted and stored.")
        return redirect("post_detail", post_id=post.id)

    return render(request, "post_new.html", {"form": form})


@needs_key
def post_detail_view(request, dek, post_id: int):
    post = get_object_or_404(Post.objects.select_related("user"), id=post_id)
    mine = post.user_id == request.user.id

    if not mine and not post.is_public:
        flash.error(request, "That post is not yours to read.")
        return redirect("index")

    try:
        if mine:
            post_key = keys.unwrap_post_key_for_owner(post.key_owner, dek)
        else:
            post_key = keys.unwrap_post_key_for_public(post.key_public)
        title, body, intact = _decrypt_post(post, post_key)
    except Exception:
        title, body, intact = None, None, False

    if not intact:
        flash.error(request, "This post failed its integrity check and will not be shown.")
        return redirect("index" if mine else "feed")

    return render(request, "post_detail.html", {
        "post": post, "title": title, "body": body, "mine": mine,
        "author": post.user.username,
        "cipher_preview": bytes(post.body_ct)[:24].hex(),
        "cipher_len": len(bytes(post.body_ct)),
    })


@needs_key
@require_POST
def post_visibility_view(request, dek, post_id: int):
    """Publish or unpublish. Adds or drops one wrapped key, nothing more."""
    post = get_object_or_404(Post, id=post_id, user=request.user)
    post_key = keys.unwrap_post_key_for_owner(post.key_owner, dek)

    if post.is_public:
        post.is_public = False
        post.key_public = None
        post.key_public_kek_id = None
        flash.success(request, "Taken off the feed. The server can no longer open this post.")
    else:
        post.is_public = True
        post.key_public = keys.wrap_post_key_for_public(post_key)
        post.key_public_kek_id = get_active_kek()[1]
        flash.success(request, "Published. The post itself was not re-encrypted.")

    post.save(update_fields=["is_public", "key_public", "key_public_kek_id"])
    return redirect("post_detail", post_id=post.id)


@needs_key
def post_delete_view(request, dek, post_id: int):
    post = get_object_or_404(Post, id=post_id, user=request.user)

    if request.method == "POST":
        post.delete()
        flash.success(request, "Deleted.")
        return redirect("index")

    try:
        post_key = keys.unwrap_post_key_for_owner(post.key_owner, dek)
        title = _decrypt_post(post, post_key)[0]
    except Exception:
        title = None

    return render(request, "post_delete_confirm.html",
                  {"post": post, "title": title or "this post"})


# ---------------------------------------------------------------- messages

@needs_key
def messages_inbox_view(request, dek):
    user = request.user
    private_key = _open_private_key(user, dek)

    inbox = []
    for message in Message.objects.filter(recipient=user).select_related("sender"):
        try:
            session_key = rsa_unwrap_session_key(private_key, message.key_for_recipient)
            title, _, intact = _message_row(message, session_key)
        except Exception:
            title, intact = None, False
        inbox.append({
            "id": message.id,
            "title": title or "could not be verified",
            "intact": intact,
            "unread": message.read_at is None,
            "sender": "Anonymous" if message.is_anonymous or not message.sender
                      else message.sender.username,
            "created_at": message.created_at,
        })

    return render(request, "messages_inbox.html", {"inbox": inbox})


@needs_key
def messages_sent_view(request, dek):
    """The outbox. Readable because the sender kept a second copy of each
    session key, wrapped under their own public key."""
    user = request.user
    private_key = _open_private_key(user, dek)

    sent = []
    for message in Message.objects.filter(sender=user).select_related("recipient"):
        try:
            session_key = rsa_unwrap_session_key(private_key, message.key_for_sender)
            title, _, intact = _message_row(message, session_key)
        except Exception:
            title, intact = None, False
        sent.append({
            "id": message.id,
            "title": title or "could not be verified",
            "intact": intact,
            "to": message.recipient.username,
            "read": message.read_at is not None,
            "created_at": message.created_at,
        })

    return render(request, "messages_sent.html", {"sent": sent})


@needs_key
def message_new_view(request, dek, to: str = ""):
    form = MessageForm(request.POST or None, initial={"to": to})

    if request.method == "POST" and form.is_valid():
        recipient = Account.objects.get(username=form.cleaned_data["to"])
        anonymous = form.cleaned_data["anonymous"]

        session_key = new_key()
        message = Message(recipient=recipient,
                          sender=None if anonymous else request.user,
                          is_anonymous=anonymous)
        message.title_nonce, message.title_ct = aead_encrypt(
            session_key, form.cleaned_data["title"].encode(), AAD_MSG_TITLE)
        message.body_nonce, message.body_ct = aead_encrypt(
            session_key, form.cleaned_data["body"].encode(), AAD_MSG_BODY)
        message.mac = row_mac(session_key, CTX_MESSAGE, str(recipient.id).encode(),
                              message.title_nonce, message.title_ct,
                              message.body_nonce, message.body_ct)

        message.key_for_recipient = rsa_wrap_session_key(
            load_public_key_from_pem(recipient.public_key_pem.encode()), session_key)
        if not anonymous:
            # a second wrapping, so the sender can still read their own outbox
            message.key_for_sender = rsa_wrap_session_key(
                load_public_key_from_pem(request.user.public_key_pem.encode()), session_key)
        message.save()

        flash.success(request, f"Sealed with {recipient.username}'s public key and sent.")
        return redirect("messages_inbox" if anonymous else "messages_sent")

    recipient = Account.objects.filter(username__iexact=to).first() if to else None
    return render(request, "message_new.html", {"form": form, "recipient": recipient})


@needs_key
def message_detail_view(request, dek, msg_id: int):
    message = get_object_or_404(
        Message.objects.select_related("sender", "recipient"), id=msg_id)

    if message.recipient_id != request.user.id and message.sender_id != request.user.id:
        flash.error(request, "That message is not addressed to you.")
        return redirect("messages_inbox")

    as_recipient = message.recipient_id == request.user.id
    wrapped = message.key_for_recipient if as_recipient else message.key_for_sender

    try:
        session_key = rsa_unwrap_session_key(_open_private_key(request.user, dek), wrapped)
        title, body, intact = _message_row(message, session_key)
    except Exception:
        title, body, intact = None, None, False

    if not intact:
        flash.error(request, "This message failed its integrity check and will not be shown.")
        return redirect("messages_inbox")

    if as_recipient and message.read_at is None:
        message.read_at = timezone.now()
        message.save(update_fields=["read_at"])

    hidden = message.is_anonymous and as_recipient
    other = message.sender if as_recipient else message.recipient
    return render(request, "message_detail.html", {
        "message": message,
        "title": title,
        "body": body,
        "as_recipient": as_recipient,
        "counterparty": "Anonymous" if hidden else (other.username if other else "a deleted account"),
        "can_reply": as_recipient and not hidden and other is not None,
        "fingerprint": "" if hidden or other is None else other.key_fingerprint,
        "wrapped_len": len(bytes(wrapped)),
    })


@login_required
def directory_view(request):
    """Who you can write to, and the fingerprint to check them against."""
    people = (Account.objects.exclude(id=request.user.id)
              .exclude(public_key_pem="").order_by("username"))
    return render(request, "directory.html", {
        "people": [{"username": p.username, "fingerprint": p.key_fingerprint} for p in people],
        "mine": request.user.key_fingerprint,
    })
