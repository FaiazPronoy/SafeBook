from django.contrib.auth import get_user_model
from keymgmt.services import get_active_kek

from . import keys
from .crypto import aead_decrypt, aead_encrypt, new_key
from .friends import friend_ids
from .mac import CTX_COMMENT, CTX_MESSAGE, CTX_POST, mac_ok, row_mac
from .models import Post, PostShare
from .rsa_utils import load_private_key_from_der, load_public_key_from_pem, rsa_wrap_session_key

Account = get_user_model()

AAD_EMAIL = b"account.email"
AAD_PHONE = b"account.phone"
AAD_PRIVKEY = b"account.private_key"
AAD_POST_BODY = b"post.body"
AAD_COMMENT_BODY = b"comment.body"
AAD_MSG_BODY = b"message.body"


def seal_post(post, post_key, body):
    post.body_nonce, post.body_ct = aead_encrypt(post_key, body.encode(), AAD_POST_BODY)
    post.mac = row_mac(post_key, CTX_POST, str(post.user_id).encode(),
                       post.body_nonce, post.body_ct)


def open_post_body(post, post_key):
    if not mac_ok(post.mac, post_key, CTX_POST, str(post.user_id).encode(),
                  post.body_nonce, post.body_ct):
        return None
    return aead_decrypt(post_key, post.body_nonce, post.body_ct, AAD_POST_BODY).decode()


def set_audience(post, post_key, audience, friends):
    post.audience = audience
    if audience == Post.PUBLIC:
        post.key_public = keys.wrap_post_key_for_public(post_key)
        post.key_public_kek_id = get_active_kek()[1]
    else:
        post.key_public = None
        post.key_public_kek_id = None
    post.save()

    if audience == Post.FRIENDS:
        hand_out(post, post_key, friends)
    else:
        post.shares.all().delete()


def hand_out(post, post_key, friends):
    have = set(post.shares.values_list("reader_id", flat=True))
    PostShare.objects.bulk_create([
        PostShare(post=post, reader=friend,
                  wrapped_key=keys.wrap_post_key_for_friend(post_key, friend))
        for friend in friends if friend.id not in have and friend.public_key_pem
    ])


def catch_up(ring):
    friends = list(Account.objects.filter(id__in=ring.friend_ids))
    if not friends:
        return 0
    given = 0
    for post in Post.objects.filter(user=ring.user, audience=Post.FRIENDS).prefetch_related("shares"):
        have = {s.reader_id for s in post.shares.all()}
        missing = [f for f in friends if f.id not in have]
        if missing:
            hand_out(post, keys.unwrap_post_key_for_owner(post.key_owner, ring.dek), missing)
            given += len(missing)
    return given


def seal_comment(comment, post_key, body):
    comment.body_nonce, comment.body_ct = aead_encrypt(post_key, body.encode(), AAD_COMMENT_BODY)
    comment.mac = row_mac(post_key, CTX_COMMENT, str(comment.post_id).encode(),
                          str(comment.author_id).encode(), comment.body_nonce, comment.body_ct)


def open_comment(comment, post_key):
    if not mac_ok(comment.mac, post_key, CTX_COMMENT, str(comment.post_id).encode(),
                  str(comment.author_id).encode(), comment.body_nonce, comment.body_ct):
        return None
    return aead_decrypt(post_key, comment.body_nonce, comment.body_ct, AAD_COMMENT_BODY).decode()


def seal_message(message, body):
    session_key = new_key()
    message.body_nonce, message.body_ct = aead_encrypt(session_key, body.encode(), AAD_MSG_BODY)
    message.mac = row_mac(session_key, CTX_MESSAGE, str(message.sender_id).encode(),
                          str(message.recipient_id).encode(), message.body_nonce, message.body_ct)
    message.key_for_recipient = rsa_wrap_session_key(
        load_public_key_from_pem(message.recipient.public_key_pem.encode()), session_key)
    message.key_for_sender = rsa_wrap_session_key(
        load_public_key_from_pem(message.sender.public_key_pem.encode()), session_key)


def open_message(message, private_key, me_id):
    wrapped = message.key_for_recipient if message.recipient_id == me_id else message.key_for_sender
    try:
        session_key = keys.unwrap_post_key_as_friend(wrapped, private_key)
    except Exception:
        return None
    if not mac_ok(message.mac, session_key, CTX_MESSAGE, str(message.sender_id).encode(),
                  str(message.recipient_id).encode(), message.body_nonce, message.body_ct):
        return None
    return aead_decrypt(session_key, message.body_nonce, message.body_ct, AAD_MSG_BODY).decode()


class Keyring:
    OK, LOCKED, BROKEN = "ok", "locked", "broken"

    def __init__(self, user, dek):
        self.user = user
        self.dek = dek
        self._private_key = None
        self._friend_ids = None

    @property
    def private_key(self):
        if self._private_key is None:
            der = aead_decrypt(self.dek, self.user.privkey_nonce, self.user.privkey_ct, AAD_PRIVKEY)
            self._private_key = load_private_key_from_der(der)
        return self._private_key

    @property
    def friend_ids(self):
        if self._friend_ids is None:
            self._friend_ids = friend_ids(self.user)
        return self._friend_ids

    def post_key(self, post):
        try:
            if post.user_id == self.user.id:
                return self.OK, keys.unwrap_post_key_for_owner(post.key_owner, self.dek)
            if post.audience == Post.PUBLIC:
                return self.OK, keys.unwrap_post_key_for_public(post.key_public)
            if post.audience == Post.FRIENDS:
                share = next((s for s in post.shares.all() if s.reader_id == self.user.id), None)
                if share is None:
                    return self.LOCKED, None
                return self.OK, keys.unwrap_post_key_as_friend(share.wrapped_key, self.private_key)
            return self.LOCKED, None
        except Exception:
            return self.BROKEN, None
