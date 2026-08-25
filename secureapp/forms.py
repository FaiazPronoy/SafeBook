from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password

Account = get_user_model()

_TEXT = {"class": "input", "autocapitalize": "none", "spellcheck": "false"}


def _pw(placeholder, autocomplete):
    return forms.PasswordInput(attrs={"class": "input", "placeholder": placeholder,
                                      "autocomplete": autocomplete})


class RegisterForm(forms.Form):
    username = forms.CharField(max_length=150, label="Username",
                               widget=forms.TextInput(attrs={**_TEXT, "placeholder": "pick a name",
                                                             "autocomplete": "username",
                                                             "autofocus": "autofocus"}))
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
        if Account.objects.filter(username__iexact=name).exists():
            raise forms.ValidationError("That username is taken.")
        return name

    def clean(self):
        data = super().clean()
        p1, p2 = data.get("password1"), data.get("password2")
        if p1 and p2 and p1 != p2:
            self.add_error("password2", "The two passwords do not match.")
        elif p1:
            # the password is also the key that unlocks the account's data, so
            # it goes through the same strength rules as any other password
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


class ChangePasswordForm(forms.Form):
    """Changing the password re-wraps the DEK. No post is re-encrypted."""

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


class PostForm(forms.Form):
    title = forms.CharField(max_length=200, label="Title",
                            widget=forms.TextInput(attrs={"class": "input", "placeholder": "a short title",
                                                          "autofocus": "autofocus"}))
    body = forms.CharField(label="Body",
                           widget=forms.Textarea(attrs={"class": "input", "rows": 10,
                                                        "placeholder": "this is encrypted before it is stored"}))
    is_public = forms.BooleanField(required=False, label="Publish to the public feed")


class MessageForm(forms.Form):
    to = forms.CharField(max_length=150, label="To",
                         widget=forms.TextInput(attrs={**_TEXT, "placeholder": "username",
                                                       "autofocus": "autofocus"}))
    title = forms.CharField(max_length=200, label="Subject",
                            widget=forms.TextInput(attrs={"class": "input", "placeholder": "subject"}))
    body = forms.CharField(label="Message",
                           widget=forms.Textarea(attrs={"class": "input", "rows": 8,
                                                        "placeholder": "sealed with the recipient's public key"}))
    anonymous = forms.BooleanField(required=False, label="Send without my name")

    def clean_to(self):
        name = self.cleaned_data["to"].strip()
        recipient = Account.objects.filter(username__iexact=name).first()
        if recipient is None:
            raise forms.ValidationError("No account with that username.")
        if not recipient.public_key_pem:
            raise forms.ValidationError(
                "That account has no messaging key yet, so nothing can be sealed for it."
            )
        return recipient.username
