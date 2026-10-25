import re

from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password

Account = get_user_model()

_TEXT = {"class": "input", "autocapitalize": "none", "spellcheck": "false"}


def _pw(placeholder, autocomplete):
    return forms.PasswordInput(attrs={"class": "input", "placeholder": placeholder,
                                      "autocomplete": autocomplete})


class RegisterForm(forms.Form):
    name = forms.CharField(max_length=60, label="Your name",
                           widget=forms.TextInput(attrs={"class": "input", "placeholder": "what friends call you",
                                                         "autocomplete": "name", "autofocus": "autofocus"}))
    username = forms.CharField(max_length=30, label="Username",
                               widget=forms.TextInput(attrs={**_TEXT, "placeholder": "for your profile link",
                                                             "autocomplete": "username"}))
    password1 = forms.CharField(label="Password", widget=_pw("at least 8 characters", "new-password"))
    password2 = forms.CharField(label="Confirm password", widget=_pw("again", "new-password"))
    email = forms.EmailField(label="Email",
                             widget=forms.EmailInput(attrs={**_TEXT, "placeholder": "you@example.com",
                                                            "autocomplete": "email"}))
    phone = forms.CharField(max_length=20, label="Phone",
                            widget=forms.TextInput(attrs={**_TEXT, "placeholder": "01XXXXXXXXX",
                                                          "autocomplete": "tel-national"}))

    def clean_username(self):
        name = self.cleaned_data["username"].strip()
        if not re.fullmatch(r"[A-Za-z0-9_.]{3,30}", name):
            raise forms.ValidationError("3 to 30 letters, digits, dots or underscores.")
        if Account.objects.filter(username__iexact=name).exists():
            raise forms.ValidationError("That username is taken.")
        return name

    def clean(self):
        data = super().clean()
        p1, p2 = data.get("password1"), data.get("password2")
        if p1 and p2 and p1 != p2:
            self.add_error("password2", "The two passwords do not match.")
        elif p1:
            # this password is also the key to the account's data, so a weak one
            # is a weak lock and not just a weak login
            try:
                validate_password(p1)
            except forms.ValidationError as exc:
                self.add_error("password1", exc)
        return data


class LoginForm(forms.Form):
    username = forms.CharField(label="Username",
                               widget=forms.TextInput(attrs={**_TEXT, "placeholder": "username",
                                                             "autocomplete": "username",
                                                             "autofocus": "autofocus"}))
    password = forms.CharField(label="Password", widget=_pw("your password", "current-password"))


class CodeForm(forms.Form):
    code = forms.CharField(label="6 digit code", min_length=6, max_length=6,
                           widget=forms.TextInput(attrs={"class": "input code", "placeholder": "000000",
                                                         "inputmode": "numeric", "autocomplete": "one-time-code",
                                                         "pattern": "[0-9]{6}", "autofocus": "autofocus"}))

    def clean_code(self):
        code = self.cleaned_data["code"].strip()
        if not code.isdigit():
            raise forms.ValidationError("The code is 6 digits.")
        return code


class ConfirmPasswordForm(forms.Form):
    password = forms.CharField(label="Your password", widget=_pw("your password", "current-password"))


class ChangePasswordForm(forms.Form):
    """Changing the password re-wraps the DEK. No note is re-encrypted."""
    current = forms.CharField(label="Current password", widget=_pw("current password", "current-password"))
    new1 = forms.CharField(label="New password", widget=_pw("new password", "new-password"))
    new2 = forms.CharField(label="Confirm new password", widget=_pw("again", "new-password"))

    def clean(self):
        data = super().clean()
        n1, n2 = data.get("new1"), data.get("new2")
        if n1 and n2 and n1 != n2:
            self.add_error("new2", "The two passwords do not match.")
        elif n1:
            try:
                validate_password(n1)
            except forms.ValidationError as exc:
                self.add_error("new1", exc)
        return data


class RecoverForm(forms.Form):
    username = forms.CharField(label="Username",
                               widget=forms.TextInput(attrs={**_TEXT, "placeholder": "username",
                                                             "autofocus": "autofocus"}))
    code = forms.CharField(label="Recovery code",
                           widget=forms.TextInput(attrs={**_TEXT, "placeholder": "XXXXX-XXXXX-XXXXX-XXXXX",
                                                         "autocomplete": "off"}))
    new1 = forms.CharField(label="New password", widget=_pw("new password", "new-password"))
    new2 = forms.CharField(label="Confirm new password", widget=_pw("again", "new-password"))

    def clean(self):
        data = super().clean()
        n1, n2 = data.get("new1"), data.get("new2")
        if n1 and n2 and n1 != n2:
            self.add_error("new2", "The two passwords do not match.")
        elif n1:
            try:
                validate_password(n1)
            except forms.ValidationError as exc:
                self.add_error("new1", exc)
        return data


class ProfileForm(forms.Form):
    name = forms.CharField(max_length=60, label="Name",
                           widget=forms.TextInput(attrs={"class": "input", "autocomplete": "name"}))
    bio = forms.CharField(max_length=160, required=False, label="Bio",
                          widget=forms.TextInput(attrs={"class": "input",
                                                        "placeholder": "a line about you, anyone can see it"}))


class PostForm(forms.Form):
    body = forms.CharField(max_length=5000, label="Post",
                           widget=forms.Textarea(attrs={"class": "input", "rows": 3,
                                                        "placeholder": "What's on your mind?"}))
    audience = forms.ChoiceField(choices=[("friends", "Friends"), ("public", "Public"), ("me", "Only me")],
                                 initial="friends", label="Who can read it")


class CommentForm(forms.Form):
    body = forms.CharField(max_length=1000, label="Comment",
                           widget=forms.TextInput(attrs={"class": "input", "placeholder": "Write a comment",
                                                         "autocomplete": "off"}))


class MessageForm(forms.Form):
    body = forms.CharField(max_length=2000, label="Message",
                           widget=forms.Textarea(attrs={"class": "input", "rows": 1,
                                                        "placeholder": "Write a message",
                                                        "autofocus": "autofocus"}))
