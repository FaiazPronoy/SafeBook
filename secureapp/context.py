from .models import FriendRequest, Message


def badges(request):
    if not request.user.is_authenticated:
        return {}
    return {
        "unread_count": Message.objects.filter(recipient=request.user, read_at__isnull=True).count(),
        "request_count": FriendRequest.objects.filter(to_user=request.user,
                                                      accepted_at__isnull=True).count(),
    }
