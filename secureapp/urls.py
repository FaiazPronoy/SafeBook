# secureapp/urls.py
from django.urls import path
from .views import (
    register_view, login_view, logout_view,
    index_view, feed_view,
    post_new_view, post_detail_view,
    messages_inbox_view, message_new_view, message_detail_view, post_delete_view
)

urlpatterns = [
    path("", index_view, name="index"),
    path("feed/", feed_view, name="feed"),             # NEW
    path("register/", register_view, name="register"),
    path("login/", login_view, name="login"),
    path("logout/", logout_view, name="logout"),
    path("posts/<int:post_id>/delete/", post_delete_view, name="post_delete"),

    path("posts/new/", post_new_view, name="post_new"),
    path("posts/<int:post_id>/", post_detail_view, name="post_detail"),

    path("messages/", messages_inbox_view, name="messages_inbox"),
    path("messages/new/", message_new_view, name="message_new"),
    path("messages/<int:msg_id>/", message_detail_view, name="message_detail"),
]
