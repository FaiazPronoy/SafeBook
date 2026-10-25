import functools

from django.contrib import messages as flash
from django.contrib.auth import get_user_model, login as django_login, logout as django_logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import check_password
from django.db import transaction
from django.shortcuts import redirect, render
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.http import require_POST

from keymgmt.services import get_active_kek

from . import keys, two_step
from .auth_utils import (MAX_FAILURES, check_credentials, clear_failures,
                         is_locked_out, record_attempt, recent_failures)
from .crypto import aead_decrypt, aead_encrypt, new_key
from .demo import PEOPLE, demo_people
from .forms import (ChangePasswordForm, CodeForm, ConfirmPasswordForm, LoginForm, ProfileForm,
                    RecoverForm, RegisterForm)
from .keyring import AAD_EMAIL, AAD_PHONE, AAD_PRIVKEY, Keyring
from .models import LoginAttempt, Post
from .recovery import new_recovery_code, normalise
from .rsa_utils import generate_rsa_keypair
from .session_keys import arm_session, disarm_session, read_private_dek

Account = get_user_model()
DEMO_USERNAMES = {p[0] for p in PEOPLE}


def _email_of(user, dek: bytes) -> str:
    return aead_decrypt(dek, user.email_nonce, user.email_ct, AAD_EMAIL).decode() if user.email_ct else ""


def _safe_next(request, target: str) -> str:
    return target if url_has_allowed_host_and_scheme(target, {request.get_host()}) else "index"


def _finish_login(request, user, dek: bytes, target: str):
    record_attempt(request, user.username, True)
    clear_failures(user.username)
    django_login(request, user)
    response = redirect(target or "index")
    arm_session(request, response, dek)
    return response


def needs_key(view):
    @functools.wraps(view)
    @login_required
    def wrapper(request, *args, **kwargs):
        dek = read_private_dek(request)
        if dek is None:
            flash.info(request, "Please sign in again to unlock your account.")
            return redirect("login")
        return view(request, Keyring(request.user, dek), *args, **kwargs)
    return wrapper


def register_view(request):
    if request.user.is_authenticated:
        return redirect("index")

    form = RegisterForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        password = form.cleaned_data["password1"]
        code = new_recovery_code()

        with transaction.atomic():
            user = Account.objects.create_user(
                username=form.cleaned_data["username"], password=password,
                display_name=form.cleaned_data["name"].strip(),
            )
            dek = new_key()

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
            return render(request, "registration/login.html", {"form": form, "demo": demo_people(Account)})

        user = check_credentials(username, password)
        if user is None:
            record_attempt(request, username, False)
            left = MAX_FAILURES - recent_failures(username)
            flash.error(request, "Wrong username or password."
                                 + (f" {left} attempts left." if left <= 2 else ""))
            return render(request, "registration/login.html", {"form": form, "demo": demo_people(Account)})

        try:
            dek = keys.open_private_dek(user.pdek_wrapped, user.pdek_salt, password)
        except Exception:
            record_attempt(request, username, False)
            flash.error(request, "Something is wrong with this account's key. "
                                 "Use your recovery code to set a new password.")
            return redirect("recover")

        target = _safe_next(request, request.POST.get("next", ""))
        email = _email_of(user, dek)
        if not user.two_step or not email:
            return _finish_login(request, user, dek, target)

        two_step.send_code(request, two_step.LOGIN_SLOT, email, "finish signing in",
                           user=user.pk, next=target, masked=two_step.mask_email(email))
        response = redirect("login_verify")
        arm_session(request, response, dek, two_step.PENDING_FIELD, two_step.PENDING_COOKIE)
        return response

    return render(request, "registration/login.html", {"form": form, "demo": demo_people(Account)})


def login_verify_view(request):
    pending = request.session.get(two_step.LOGIN_SLOT)
    dek = read_private_dek(request, two_step.PENDING_FIELD, two_step.PENDING_COOKIE)
    user = Account.objects.filter(pk=pending["user"]).first() if pending else None
    if user is None or dek is None:
        request.session.pop(two_step.LOGIN_SLOT, None)
        flash.info(request, "Sign in again to get a new code.")
        return redirect("login")

    form = CodeForm(request.POST or None)
    if request.method == "POST" and request.POST.get("action") == "resend":
        if two_step.can_resend(request, two_step.LOGIN_SLOT):
            two_step.send_code(request, two_step.LOGIN_SLOT, _email_of(user, dek), "finish signing in")
            flash.success(request, "A new code is on its way.")
        else:
            flash.info(request, "Wait a minute before asking for another code.")
        return redirect("login_verify")

    if request.method == "POST" and form.is_valid():
        result = two_step.check_code(request, two_step.LOGIN_SLOT, form.cleaned_data["code"])
        if result == "ok":
            response = _finish_login(request, user, dek, pending["next"])
            disarm_session(request, response, two_step.PENDING_FIELD, two_step.PENDING_COOKIE)
            return response
        record_attempt(request, user.username, False)
        if result == "wrong" and not is_locked_out(user.username):
            flash.error(request, "That code is not right. Check the latest email and try again.")
        else:
            response = redirect("login")
            disarm_session(request, response, two_step.PENDING_FIELD, two_step.PENDING_COOKIE)
            flash.error(request, "That code has expired or was wrong too many times. Sign in again.")
            return response

    return render(request, "registration/login_verify.html", {"form": form, "email": pending["masked"]})


@require_POST
def logout_view(request):
    idle = request.POST.get("reason") == "idle"
    django_logout(request)
    response = redirect("login")
    disarm_session(request, response)
    flash.info(request, "Locked after 15 minutes without activity. Sign in to pick up where you left off."
               if idle else "Signed out.")
    return response


def recover_view(request):
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
            user.rec_salt, user.rec_wrapped = keys.seal_recovery_dek(dek, normalise(fresh_code))
            user.rec_used_at = timezone.now()
            user.save()
        clear_failures(user.username)

        request.session["fresh_recovery_code"] = fresh_code
        request.session["fresh_recovery_user"] = user.username
        return redirect("recovery_code")

    return render(request, "recover.html", {"form": form})


@needs_key
def account_view(request, ring):
    user, dek = request.user, ring.dek
    email = _email_of(user, dek)
    phone = aead_decrypt(dek, user.phone_nonce, user.phone_ct, AAD_PHONE).decode() if user.phone_ct else ""

    mine = Post.objects.filter(user=user)
    return render(request, "account.html", {
        "email": email,
        "phone": phone,
        "fingerprint": user.key_fingerprint,
        "attempts": LoginAttempt.objects.filter(username=user.username)[:12],
        "form": ChangePasswordForm(),
        "code_form": CodeForm(),
        "password_form": ConfirmPasswordForm(),
        "setup_pending": two_step.SETUP_SLOT in request.session,
        "is_demo": user.username in DEMO_USERNAMES,
        "profile_form": ProfileForm(initial={"name": user.display_name, "bio": user.bio}),
        "kek_id": get_active_kek()[1],
        "envelope_hex": bytes(user.pdek_wrapped).hex() if user.pdek_wrapped else "",
        "counts": {a: mine.filter(audience=a).count() for a in (Post.ONLY_ME, Post.FRIENDS, Post.PUBLIC)},
    })


@login_required
@require_POST
def profile_edit_view(request):
    form = ProfileForm(request.POST)
    if form.is_valid():
        request.user.display_name = form.cleaned_data["name"].strip()
        request.user.bio = form.cleaned_data["bio"].strip()
        request.user.save(update_fields=["display_name", "bio"])
        flash.success(request, "Profile updated.")
    else:
        for error in form.errors.values():
            flash.error(request, error[0])
    return redirect("account")


@needs_key
@require_POST
def change_password_view(request, ring):
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
        user.pdek_salt, user.pdek_wrapped = keys.seal_private_dek(ring.dek, new_password)
        user.save()

    django_login(request, user)
    response = redirect("account")
    arm_session(request, response, ring.dek)
    flash.success(request, "Password changed. Nothing you have posted was touched.")
    return response


@needs_key
@require_POST
def two_step_start_view(request, ring):
    user = request.user
    email = _email_of(user, ring.dek)
    if user.username in DEMO_USERNAMES:
        flash.error(request, "Two-step sign in stays off on demo accounts, so everyone can still try them.")
    elif not email:
        flash.error(request, "Add an email address first.")
    else:
        two_step.send_code(request, two_step.SETUP_SLOT, email, "turn on two-step sign in")
        flash.success(request, f"We sent a code to {two_step.mask_email(email)}.")
    return redirect("account")


@login_required
@require_POST
def two_step_confirm_view(request):
    form = CodeForm(request.POST)
    result = two_step.check_code(request, two_step.SETUP_SLOT, form.cleaned_data["code"]) \
        if form.is_valid() else "wrong"
    if result == "ok":
        request.user.two_step = True
        request.user.save(update_fields=["two_step"])
        flash.success(request, "Two-step sign in is on. Each sign in now asks for a code from your email.")
    elif result == "wrong":
        flash.error(request, "That code is not right.")
    else:
        flash.error(request, "That code has expired. Ask for a new one.")
    return redirect("account")


@login_required
@require_POST
def two_step_cancel_view(request):
    request.session.pop(two_step.SETUP_SLOT, None)
    return redirect("account")


@login_required
@require_POST
def two_step_off_view(request):
    form = ConfirmPasswordForm(request.POST)
    if form.is_valid() and check_password(form.cleaned_data["password"], request.user.password):
        request.user.two_step = False
        request.user.save(update_fields=["two_step"])
        flash.success(request, "Two-step sign in is off.")
    else:
        flash.error(request, "That is not your password.")
    return redirect("account")
