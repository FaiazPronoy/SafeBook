"""Chat. Every message is sealed for the two people in the conversation and
nobody else, the server included."""
from django.contrib import messages as flash
from django.contrib.auth import get_user_model
from django.db.models import Q
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone

from .forms import MessageForm
from .keyring import open_message, seal_message
from .models import Message
from .views import needs_key

Account = get_user_model()


def _conversations(ring):
    """Everyone this person has chatted with, newest first, plus friends
    they have not written to yet so there is someone to start with."""
    me = ring.user
    latest = {}
    for m in (Message.objects.filter(Q(sender=me) | Q(recipient=me))
              .select_related("sender", "recipient").order_by("-created_at")):
        other = m.recipient if m.sender_id == me.id else m.sender
        if other.id not in latest:
            latest[other.id] = (other, m)

    unread = {}
    for sender_id in Message.objects.filter(recipient=me, read_at__isnull=True).values_list("sender_id", flat=True):
        unread[sender_id] = unread.get(sender_id, 0) + 1

    rows = []
    for other, m in latest.values():
        preview = open_message(m, ring.private_key, me.id)
        rows.append({"person": other, "at": m.created_at, "mine": m.sender_id == me.id,
                     "preview": preview if preview is not None else "A message here could not be opened.",
                     "unread": unread.get(other.id, 0)})
    fresh = Account.objects.filter(id__in=ring.friend_ids - set(latest)).order_by("display_name")
    rows += [{"person": p, "at": None, "preview": "Say hello", "unread": 0} for p in fresh]
    return rows


@needs_key
def inbox_view(request, ring):
    return render(request, "chat.html", {"conversations": _conversations(ring), "other": None})


@needs_key
def thread_view(request, ring, username: str):
    me = ring.user
    other = get_object_or_404(Account, username__iexact=username)
    if other.id == me.id or not other.public_key_pem:
        return redirect("messages_inbox")

    form = MessageForm(request.POST or None)
    if request.method == "POST":
        if form.is_valid():
            message = Message(sender=me, recipient=other)
            seal_message(message, form.cleaned_data["body"])
            message.save()
        return redirect("message_thread", username=other.username)

    rows = (Message.objects.filter(Q(sender=me, recipient=other) | Q(sender=other, recipient=me))
            .order_by("created_at"))
    thread, broken = [], 0
    for m in rows:
        body = open_message(m, ring.private_key, me.id)
        if body is None:
            broken += 1
            continue
        thread.append({"m": m, "body": body, "mine": m.sender_id == me.id})
    if broken:
        flash.error(request, f"{broken} message{'s' if broken > 1 else ''} in this chat could "
                             "not be opened, so they are not being shown.")

    Message.objects.filter(sender=other, recipient=me, read_at__isnull=True).update(read_at=timezone.now())
    return render(request, "chat.html", {
        "conversations": _conversations(ring),
        "other": other,
        "thread": thread,
        "form": form,
        "is_friend": other.id in ring.friend_ids,
    })
