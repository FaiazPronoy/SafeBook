"""Who is friends with whom.

A friendship is an accepted FriendRequest, whichever way round it was sent.
None of this is encrypted: the server has to know who your friends are to
know whose keys to hand a friends-only post to. The about page says so.
"""
from django.db.models import Q

from .models import FriendRequest


def friend_ids(user) -> set[int]:
    rows = (FriendRequest.objects.filter(accepted_at__isnull=False)
            .filter(Q(from_user=user) | Q(to_user=user))
            .values_list("from_user_id", "to_user_id"))
    return {b if a == user.id else a for a, b in rows}


def between(a, b):
    """The request between two people, whichever way it went, or None."""
    return (FriendRequest.objects
            .filter(Q(from_user=a, to_user=b) | Q(from_user=b, to_user=a))
            .first())


def relation(me, other) -> str:
    """self, friends, sent, received or none: what the profile button says."""
    if me.id == other.id:
        return "self"
    request = between(me, other)
    if request is None:
        return "none"
    if request.accepted_at:
        return "friends"
    return "sent" if request.from_user_id == me.id else "received"
