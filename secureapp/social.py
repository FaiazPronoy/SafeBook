from django.contrib import messages as flash
from django.contrib.auth import get_user_model
from django.db.models import Count, Prefetch, Q
from django.http import Http404, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.http import require_POST

from . import keys
from .demo import demo_people
from .forms import CommentForm, PostForm
from .friends import between, relation
from .keyring import (Keyring, catch_up, open_comment, open_post_body, seal_comment,
                      seal_post, set_audience)
from .models import Comment, FriendRequest, Like, Post, PostShare
from .views import needs_key

Account = get_user_model()

FEED_SIZE = 40


def _back(request, fallback="index", **kwargs):
    target = request.POST.get("next", "")
    if target and url_has_allowed_host_and_scheme(target, {request.get_host()}):
        return redirect(target)
    return redirect(fallback, **kwargs)


def _posts_for(ring, rows, all_comments=False):
    posts = list(rows.select_related("user").prefetch_related(
        Prefetch("shares", queryset=PostShare.objects.filter(reader=ring.user)),
        Prefetch("comments", queryset=Comment.objects.select_related("author")),
    ).annotate(like_count=Count("likes", distinct=True),
               share_count=Count("shares", distinct=True)))
    liked = set(Like.objects.filter(user=ring.user, post_id__in=[p.id for p in posts])
                .values_list("post_id", flat=True))

    shown = []
    for post in posts:
        state, post_key = ring.post_key(post)
        item = {"post": post, "author": post.user, "mine": post.user_id == ring.user.id,
                "state": state, "likes": post.like_count, "liked": post.id in liked,
                "friends_count": post.share_count}
        if state == Keyring.OK:
            item["body"] = open_post_body(post, post_key)
            if item["body"] is None:
                item["state"] = Keyring.BROKEN
            else:
                comments = list(post.comments.all())
                item["comment_count"] = len(comments)
                if not all_comments:
                    comments = comments[-2:]
                item["comments"] = [
                    {"c": c, "body": open_comment(c, post_key),
                     "can_delete": ring.user.id in (c.author_id, post.user_id)}
                    for c in comments]
        shown.append(item)
    return shown


def home_view(request):
    if not request.user.is_authenticated:
        return render(request, "landing.html", {"demo": demo_people(Account)})
    return feed_view(request)


@needs_key
def feed_view(request, ring):
    catch_up(ring)
    friends = ring.friend_ids
    newest = Post.objects.filter(
        Q(user=ring.user)
        | Q(user__in=friends, audience=Post.FRIENDS)
        | Q(audience=Post.PUBLIC)
    ).order_by("-created_at").values_list("id", flat=True)[:FEED_SIZE]
    items = _posts_for(ring, Post.objects.filter(id__in=list(newest)).order_by("-created_at"))

    return render(request, "feed.html", {
        "items": [i for i in items if i["state"] != Keyring.BROKEN],
        "unreadable": sum(1 for i in items if i["state"] == Keyring.BROKEN),
        "form": PostForm(),
        "requests": FriendRequest.objects.filter(to_user=ring.user, accepted_at__isnull=True)
                                         .select_related("from_user")[:4],
        "contacts": Account.objects.filter(id__in=friends).order_by("display_name", "username"),
    })


@needs_key
@require_POST
def post_new_view(request, ring):
    form = PostForm(request.POST)
    if not form.is_valid():
        flash.error(request, "Write something first.")
        return redirect("index")

    post_key = keys.new_post_key()
    post = Post(user=ring.user, key_owner=keys.wrap_post_key_for_owner(post_key, ring.dek))
    seal_post(post, post_key, form.cleaned_data["body"])
    friends = Account.objects.filter(id__in=ring.friend_ids)
    set_audience(post, post_key, form.cleaned_data["audience"], friends)

    flash.success(request, {
        Post.ONLY_ME: "Posted. Only you can read it.",
        Post.FRIENDS: f"Posted. Locked for you and {len(ring.friend_ids)} friends.",
        Post.PUBLIC: "Posted publicly.",
    }[post.audience])
    return _back(request)


@needs_key
def post_detail_view(request, ring, post_id: int):
    post = get_object_or_404(Post, id=post_id)
    items = _posts_for(ring, Post.objects.filter(id=post.id), all_comments=True)
    item = items[0]

    if item["state"] == Keyring.LOCKED:
        flash.error(request, "You do not hold a key for that post.")
        return redirect("index")
    if item["state"] == Keyring.BROKEN:
        flash.error(request, "This post could not be opened, so it is not being shown.")
        return redirect("index")

    holders = []
    if item["mine"]:
        holders = list(post.shares.select_related("reader").order_by("reader__username"))
    return render(request, "post_detail.html", {
        "i": item,
        "form": CommentForm(),
        "holders": holders,
        "cipher_hex": bytes(post.body_ct)[:48].hex(),
        "cipher_len": len(bytes(post.body_ct)),
        "owner_key_len": len(bytes(post.key_owner)),
        "mac_hex": bytes(post.mac or b"").hex(),
    })


@needs_key
@require_POST
def post_audience_view(request, ring, post_id: int):
    post = get_object_or_404(Post, id=post_id, user=ring.user)
    audience = request.POST.get("audience")
    if audience not in dict(Post.AUDIENCES):
        return _back(request, "post_detail", post_id=post.id)

    post_key = keys.unwrap_post_key_for_owner(post.key_owner, ring.dek)
    set_audience(post, post_key, audience, Account.objects.filter(id__in=ring.friend_ids))
    flash.success(request, {
        Post.ONLY_ME: "Now only you can read this post.",
        Post.FRIENDS: "Now your friends can read this post.",
        Post.PUBLIC: "This post is public now.",
    }[audience])
    return _back(request, "post_detail", post_id=post.id)


@needs_key
def post_edit_view(request, ring, post_id: int):
    post = get_object_or_404(Post, id=post_id, user=ring.user)
    post_key = keys.unwrap_post_key_for_owner(post.key_owner, ring.dek)
    body = open_post_body(post, post_key)
    if body is None:
        flash.error(request, "This post could not be opened, so it cannot be edited.")
        return redirect("index")

    if request.method == "POST":
        text = request.POST.get("body", "").strip()
        if not text:
            flash.error(request, "A post needs some words in it.")
        elif len(text) > 5000:
            flash.error(request, "That is longer than a post can be.")
        else:
            seal_post(post, post_key, text)
            post.edited_at = timezone.now()
            post.save(update_fields=["body_nonce", "body_ct", "mac", "edited_at"])
            flash.success(request, "Post updated.")
            return redirect("post_detail", post_id=post.id)
        body = text or body

    return render(request, "post_edit.html", {"post": post, "body": body})


@needs_key
def post_delete_view(request, ring, post_id: int):
    post = get_object_or_404(Post, id=post_id, user=ring.user)
    if request.method == "POST":
        post.delete()
        flash.success(request, "Post deleted, with every copy of its key.")
        return redirect("index")

    _, post_key = ring.post_key(post)
    body = open_post_body(post, post_key) if post_key else None
    return render(request, "post_delete_confirm.html", {"post": post, "body": body})


@needs_key
@require_POST
def post_like_view(request, ring, post_id: int):
    post = get_object_or_404(Post.objects.prefetch_related("shares"), id=post_id)
    if ring.post_key(post)[0] != Keyring.OK:
        raise Http404
    like, made = Like.objects.get_or_create(post=post, user=ring.user)
    if not made:
        like.delete()
    if request.headers.get("x-requested-with") == "fetch":
        return JsonResponse({"liked": made, "count": post.likes.count()})
    return _back(request)


@needs_key
@require_POST
def comment_new_view(request, ring, post_id: int):
    post = get_object_or_404(Post.objects.prefetch_related("shares"), id=post_id)
    state, post_key = ring.post_key(post)
    if state != Keyring.OK:
        raise Http404

    form = CommentForm(request.POST)
    if form.is_valid():
        comment = Comment(post=post, author=ring.user)
        seal_comment(comment, post_key, form.cleaned_data["body"])
        comment.save()
    return _back(request, "post_detail", post_id=post.id)


@needs_key
@require_POST
def comment_delete_view(request, ring, comment_id: int):
    comment = get_object_or_404(
        Comment.objects.filter(Q(author=ring.user) | Q(post__user=ring.user)), id=comment_id)
    post_id = comment.post_id
    comment.delete()
    return _back(request, "post_detail", post_id=post_id)


@needs_key
def profile_view(request, ring, username: str):
    person = get_object_or_404(Account, username__iexact=username)
    if person.id == ring.user.id:
        catch_up(ring)
    rel = relation(ring.user, person)

    rows = Post.objects.filter(user=person).order_by("-created_at")
    items = _posts_for(ring, rows)
    readable = [i for i in items if i["state"] == Keyring.OK]
    waiting = sum(1 for i in items if i["state"] == Keyring.LOCKED and rel == "friends"
                  and i["post"].audience == Post.FRIENDS)

    their_friends = Account.objects.filter(
        Q(requests_sent__to_user=person, requests_sent__accepted_at__isnull=False)
        | Q(requests_received__from_user=person, requests_received__accepted_at__isnull=False)
    ).distinct()

    return render(request, "profile.html", {
        "person": person,
        "relation": rel,
        "items": readable,
        "hidden": len(items) - len(readable) - waiting,
        "waiting": waiting,
        "friends": their_friends.order_by("display_name")[:9],
        "friend_total": their_friends.count(),
        "form": PostForm() if rel == "self" else None,
    })


@needs_key
def friends_view(request, ring):
    catch_up(ring)
    me = ring.user
    q = request.GET.get("q", "").strip()
    friends = Account.objects.filter(id__in=ring.friend_ids).order_by("display_name", "username")
    pending_ids = FriendRequest.objects.filter(Q(from_user=me) | Q(to_user=me)).values_list(
        "from_user_id", "to_user_id")
    known = {me.id} | {x for pair in pending_ids for x in pair}

    others = Account.objects.exclude(id__in=known).exclude(public_key_pem="")
    if q:
        match = Q(username__icontains=q) | Q(display_name__icontains=q)
        friends = friends.filter(match)
        others = others.filter(match)

    return render(request, "friends.html", {
        "q": q,
        "friends": friends,
        "received": FriendRequest.objects.filter(to_user=me, accepted_at__isnull=True)
                                         .select_related("from_user"),
        "sent": FriendRequest.objects.filter(from_user=me, accepted_at__isnull=True)
                                     .select_related("to_user"),
        "others": others.order_by("display_name", "username")[:30],
    })


@needs_key
@require_POST
def friend_action_view(request, ring, username: str, action: str):
    me = ring.user
    other = get_object_or_404(Account, username__iexact=username)
    if other.id == me.id:
        raise Http404
    existing = between(me, other)

    if action == "add" and existing is None:
        FriendRequest.objects.create(from_user=me, to_user=other)
        flash.success(request, f"Friend request sent to {other.name}.")
    elif action == "accept" and existing and existing.to_user_id == me.id and not existing.accepted_at:
        existing.accepted_at = timezone.now()
        existing.save(update_fields=["accepted_at"])
        ring._friend_ids = None
        catch_up(ring)
        flash.success(request, f"You and {other.name} are friends now.")
    elif action in ("decline", "cancel", "remove") and existing:
        if action == "remove" and not existing.accepted_at:
            return _back(request, "profile", username=other.username)
        existing.delete()
        PostShare.objects.filter(Q(post__user=me, reader=other) | Q(post__user=other, reader=me)).delete()
        flash.info(request, {"decline": "Request declined.", "cancel": "Request cancelled.",
                             "remove": f"You are no longer friends with {other.name}."}[action])
    return _back(request, "profile", username=other.username)
