"""Fill an empty database with enough to look at.

Every account here is built through the same code path as a real
registration, so the seeded rows are encrypted exactly like anyone else's -
there is no back door that writes plaintext.
"""

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand
from django.db import transaction

from keymgmt.services import get_active_kek
from secureapp import keys
from secureapp.crypto import aead_encrypt, new_key
from secureapp.demo import PEOPLE
from secureapp.mac import CTX_MESSAGE, CTX_POST, row_mac
from secureapp.models import Message, Post
from secureapp.recovery import new_recovery_code, normalise
from secureapp.rsa_utils import generate_rsa_keypair, load_public_key_from_pem, rsa_wrap_session_key
from secureapp.views import (AAD_EMAIL, AAD_MSG_BODY, AAD_MSG_TITLE, AAD_PHONE,
                             AAD_POST_BODY, AAD_POST_TITLE, AAD_PRIVKEY)

Account = get_user_model()


POSTS = [
    ("nusrat", True, "Why I stopped trusting 'end to end' badges",
     "A padlock in a corner of the screen is a picture, not a proof. The "
     "question worth asking is which key opens the data and who is holding "
     "it. If the answer is the same company that stores it, the badge is "
     "decoration."),
    ("nusrat", False, "Recovery code, written down",
     "Kept in the same envelope as the passport. If I lose the password this "
     "is the only way back in, and nobody at SafeBook can help me."),
    ("faiaz", True, "Notes on scrypt parameters",
     "N is the memory knob. Going from 2^14 to 2^16 costs me a fifth of a "
     "second at login and costs an attacker four times as much for every "
     "guess in their wordlist. That trade is worth taking."),
    ("faiaz", False, "Bank details",
     "Account 4417, branch Mirpur. Encrypted with a key the server cannot "
     "unwrap while I am signed out."),
    ("tanvir", True, "ECB is not encryption, it is a substitution",
     "Ran the padlock picture through it in the lab page. You can still see "
     "the padlock. Same key, same cipher, different mode, completely "
     "different answer to whether anything was hidden."),
]

MESSAGES = [
    ("faiaz", "nusrat", False, "Your fingerprint",
     "Read your key fingerprint back to me over the phone before I send "
     "anything real. If it does not match what SafeBook shows me, someone "
     "has swapped a key."),
    ("nusrat", "faiaz", False, "Re: your fingerprint",
     "Checked, both ends match. Sending the draft tonight."),
    ("tanvir", "nusrat", True, "Anonymous note",
     "The report you asked about is on the shared drive. I would rather not "
     "have my name on this one."),
]


class Command(BaseCommand):
    help = "Create demo accounts, posts and messages in an empty database."

    def add_arguments(self, parser):
        parser.add_argument("--reset", action="store_true",
                            help="delete the demo accounts first")

    @transaction.atomic
    def handle(self, *args, **options):
        if options["reset"]:
            Account.objects.filter(username__in=[p[0] for p in PEOPLE]).delete()

        if Account.objects.filter(username=PEOPLE[0][0]).exists():
            self.stdout.write(self.style.WARNING(
                "The demo accounts are already here. Use --reset to rebuild them."))
            return

        deks, codes = {}, {}
        for username, password, email, phone in PEOPLE:
            user = Account.objects.create_user(username=username, password=password)
            dek = new_key()
            code = new_recovery_code()

            user.pdek_salt, user.pdek_wrapped = keys.seal_private_dek(dek, password)
            user.rec_salt, user.rec_wrapped = keys.seal_recovery_dek(dek, normalise(code))
            user.email_nonce, user.email_ct = aead_encrypt(dek, email.encode(), AAD_EMAIL)
            user.phone_nonce, user.phone_ct = aead_encrypt(dek, phone.encode(), AAD_PHONE)

            pub_pem, priv_der = generate_rsa_keypair()
            user.public_key_pem = pub_pem.decode()
            user.privkey_nonce, user.privkey_ct = aead_encrypt(dek, priv_der, AAD_PRIVKEY)
            user.save()

            deks[username], codes[username] = dek, code

        kek_id = get_active_kek()[1]
        for author, is_public, title, body in POSTS:
            user = Account.objects.get(username=author)
            post_key = keys.new_post_key()
            post = Post(user=user, is_public=is_public)
            post.key_owner = keys.wrap_post_key_for_owner(post_key, deks[author])
            if is_public:
                post.key_public = keys.wrap_post_key_for_public(post_key)
                post.key_public_kek_id = kek_id
            post.title_nonce, post.title_ct = aead_encrypt(post_key, title.encode(), AAD_POST_TITLE)
            post.body_nonce, post.body_ct = aead_encrypt(post_key, body.encode(), AAD_POST_BODY)
            post.mac = row_mac(post_key, CTX_POST, str(user.id).encode(),
                               post.title_nonce, post.title_ct, post.body_nonce, post.body_ct)
            post.save()

        for sender_name, recipient_name, anonymous, title, body in MESSAGES:
            sender = Account.objects.get(username=sender_name)
            recipient = Account.objects.get(username=recipient_name)
            session_key = new_key()

            message = Message(recipient=recipient,
                              sender=None if anonymous else sender,
                              is_anonymous=anonymous)
            message.title_nonce, message.title_ct = aead_encrypt(session_key, title.encode(), AAD_MSG_TITLE)
            message.body_nonce, message.body_ct = aead_encrypt(session_key, body.encode(), AAD_MSG_BODY)
            message.mac = row_mac(session_key, CTX_MESSAGE, str(recipient.id).encode(),
                                  message.title_nonce, message.title_ct,
                                  message.body_nonce, message.body_ct)
            message.key_for_recipient = rsa_wrap_session_key(
                load_public_key_from_pem(recipient.public_key_pem.encode()), session_key)
            if not anonymous:
                message.key_for_sender = rsa_wrap_session_key(
                    load_public_key_from_pem(sender.public_key_pem.encode()), session_key)
            message.save()

        self.stdout.write(self.style.SUCCESS(
            f"Seeded {len(PEOPLE)} accounts, {len(POSTS)} posts, {len(MESSAGES)} messages.\n"))
        self.stdout.write("Sign in with:")
        for username, password, _, _ in PEOPLE:
            self.stdout.write(f"    {username:<8} {password}    recovery {codes[username]}")
        self.stdout.write(self.style.WARNING(
            "\nThose recovery codes are printed once, here, and are not "
            "recoverable from the database afterwards."))
