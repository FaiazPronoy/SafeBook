"""What every page needs to know, whoever is looking at it."""

from .models import Message


def unread(request):
    """The number on the Messages tab. Counting rows reads no ciphertext."""
    if not request.user.is_authenticated:
        return {}
    return {"unread_count": Message.objects.filter(recipient=request.user,
                                                   read_at__isnull=True).count()}
