"""Fill an empty database with enough to look at.

Every account here is built through the same code path as a real
registration, and every post, comment and message is sealed by the same
functions the views use, so the seeded rows are encrypted exactly like
anyone else's. There is no back door that writes plaintext.
"""

from datetime import timedelta

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone

from secureapp import keys
from secureapp.crypto import aead_encrypt, new_key
from secureapp.demo import PEOPLE
from secureapp.keyring import (AAD_EMAIL, AAD_PHONE, AAD_PRIVKEY, seal_comment,
                               seal_message, seal_post, set_audience)
from secureapp.models import Comment, FriendRequest, Like, Message, Post
from secureapp.recovery import new_recovery_code, normalise
from secureapp.rsa_utils import generate_rsa_keypair

Account = get_user_model()

FRIENDS = [("nusrat", "faiaz"), ("tanvir", "nusrat"), ("nusrat", "mim"), ("faiaz", "tanvir")]
PENDING = [("mim", "faiaz")]

# author, audience, hours ago, text, [(commenter, text)], [likers]
POSTS = [
    ("tanvir", "public", 3,
     "Sunset from a rooftop in Lalbagh. Twelve floors of stairs, zero regrets. "
     "The fort looks like a painting from up here.",
     [("nusrat", "Which building? I want to go before the rains come back."),
      ("tanvir", "The blue one behind the bakery. Bring water.")],
     ["nusrat", "faiaz", "mim"]),
    ("faiaz", "friends", 6,
     "Finally moved my notes off the cloud drive I did not trust. Took a whole "
     "evening. If you need the CSE447 slides, ask me here, not on the group chat.",
     [("nusrat", "Asking here then. Week 9 please, the one on key exchange.")],
     ["nusrat"]),
    ("nusrat", "friends", 20,
     "Passed the viva. They asked why a friends-only post needs a copy of the "
     "key for every friend, and I got to draw this app on the whiteboard.",
     [("mim", "Proud of you!!"), ("faiaz", "Told you the diagram would carry it."),
      ("tanvir", "Treat is on you now.")],
     ["mim", "faiaz", "tanvir"]),
    ("nusrat", "me", 26,
     "Recovery code is in the envelope with my passport. If I forget my password "
     "this is the only way back in, and nobody at SafeBook can help me.",
     [], []),
    ("mim", "public", 30,
     "Hot take: a padlock icon in a corner is decoration, not proof. Ask who "
     "holds the key.",
     [("faiaz", "Framing this.")],
     ["faiaz", "tanvir"]),
    ("faiaz", "me", 44,
     "Bank details. Account 4417, branch Mirpur. Encrypted with a key the server "
     "cannot unwrap while I am signed out.",
     [], []),
    ("tanvir", "friends", 52,
     "Anyone free on Friday? Thinking biryani in Old Dhaka and then the "
     "riverside after dark.",
     [("faiaz", "In. Star Kabab first though."), ("nusrat", "Only if we walk back.")],
     ["faiaz", "nusrat"]),
]

# sender, recipient, minutes ago, text
CHATS = [
    ("faiaz", "nusrat", 300, "Before I send the draft: read your safety number back to me?"),
    ("nusrat", "faiaz", 296, "Checked on the phone. Both ends match."),
    ("faiaz", "nusrat", 295, "Perfect, sending it tonight."),
    ("tanvir", "nusrat", 90, "The photos from the rooftop are up, public this time."),
    ("nusrat", "tanvir", 84, "Saw them. The third one is my new wallpaper."),
    ("tanvir", "nusrat", 12, "Friday still on?"),
    ("mim", "nusrat", 40, "Can you tell Faiaz to accept my request? 😅"),
]


class Command(BaseCommand):
    help = "Create demo people, friendships, posts, comments and chats in an empty database."

    def add_arguments(self, parser):
        parser.add_argument("--reset", action="store_true",
                            help="delete the demo accounts first")

    @transaction.atomic
    def handle(self, *args, **options):
        names = [p[0] for p in PEOPLE]
        present = Account.objects.filter(username__in=names).count()
        if present and present < len(names) and not options["reset"]:
            # an older demo set, from before friends existed: only the demo
            # accounts are touched, never anyone else's
            self.stdout.write("An older set of demo accounts is here; rebuilding them.")
            options["reset"] = True
        if options["reset"]:
            Account.objects.filter(username__in=names).delete()
        elif present:
            self.stdout.write(self.style.WARNING(
                "The demo accounts are already here. Use --reset to rebuild them."))
            return

        now = timezone.now()
        people, deks, codes = {}, {}, {}
        for username, password, name, email, phone, bio in PEOPLE:
            user = Account.objects.create_user(username=username, password=password,
                                               display_name=name, bio=bio)
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

            people[username], deks[username], codes[username] = user, dek, code

        for a, b in FRIENDS:
            FriendRequest.objects.create(from_user=people[a], to_user=people[b], accepted_at=now)
        for a, b in PENDING:
            FriendRequest.objects.create(from_user=people[a], to_user=people[b])

        def friends_of(name):
            mine = {b for a, b in FRIENDS if a == name} | {a for a, b in FRIENDS if b == name}
            return [people[n] for n in mine]

        for author, audience, hours, text, comments, likers in POSTS:
            post_key = keys.new_post_key()
            post = Post(user=people[author],
                        key_owner=keys.wrap_post_key_for_owner(post_key, deks[author]))
            seal_post(post, post_key, text)
            set_audience(post, post_key, audience, friends_of(author))
            Post.objects.filter(id=post.id).update(created_at=now - timedelta(hours=hours))

            for n, (who, said) in enumerate(comments):
                comment = Comment(post=post, author=people[who])
                seal_comment(comment, post_key, said)
                comment.save()
                Comment.objects.filter(id=comment.id).update(
                    created_at=now - timedelta(hours=hours) + timedelta(minutes=20 * (n + 1)))
            for who in likers:
                Like.objects.create(post=post, user=people[who])

        for sender, recipient, minutes, text in CHATS:
            message = Message(sender=people[sender], recipient=people[recipient])
            seal_message(message, text)
            message.save()
            at = now - timedelta(minutes=minutes)
            # everything but the last word in each chat has been read
            Message.objects.filter(id=message.id).update(
                created_at=at, read_at=at + timedelta(minutes=1) if minutes > 40 else None)

        self.stdout.write(self.style.SUCCESS(
            f"Seeded {len(PEOPLE)} people, {len(FRIENDS)} friendships, {len(POSTS)} posts, "
            f"{len(CHATS)} chat messages.\n"))
        self.stdout.write("Sign in with:")
        for username, password, *_ in PEOPLE:
            self.stdout.write(f"    {username:<8} {password}    recovery {codes[username]}")
        self.stdout.write(self.style.WARNING(
            "\nThose recovery codes are printed once, here, and are not "
            "recoverable from the database afterwards."))
