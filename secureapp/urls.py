from django.urls import path

from . import chat, lab, social, views

urlpatterns = [
    path("", social.home_view, name="index"),
    path("feed/", social.feed_view, name="feed"),

    path("register/", views.register_view, name="register"),
    path("register/recovery-code/", views.recovery_code_view, name="recovery_code"),
    path("login/", views.login_view, name="login"),
    path("logout/", views.logout_view, name="logout"),
    path("recover/", views.recover_view, name="recover"),

    path("account/", views.account_view, name="account"),
    path("account/profile/", views.profile_edit_view, name="profile_edit"),
    path("account/password/", views.change_password_view, name="change_password"),

    path("posts/new/", social.post_new_view, name="post_new"),
    path("posts/<int:post_id>/", social.post_detail_view, name="post_detail"),
    path("posts/<int:post_id>/audience/", social.post_audience_view, name="post_audience"),
    path("posts/<int:post_id>/edit/", social.post_edit_view, name="post_edit"),
    path("posts/<int:post_id>/delete/", social.post_delete_view, name="post_delete"),
    path("posts/<int:post_id>/like/", social.post_like_view, name="post_like"),
    path("posts/<int:post_id>/comments/", social.comment_new_view, name="comment_new"),
    path("comments/<int:comment_id>/delete/", social.comment_delete_view, name="comment_delete"),

    path("friends/", social.friends_view, name="friends"),
    path("friends/<str:username>/<str:action>/", social.friend_action_view, name="friend_action"),
    path("u/<str:username>/", social.profile_view, name="profile"),

    path("messages/", chat.inbox_view, name="messages_inbox"),
    path("messages/<str:username>/", chat.thread_view, name="message_thread"),

    path("lab/", lab.lab_index, name="lab"),
    path("lab/modes/", lab.modes_view, name="lab_modes"),
    path("lab/nonce/", lab.nonce_view, name="lab_nonce"),
    path("lab/timing/", lab.timing_view, name="lab_timing"),
    path("lab/kdf/", lab.kdf_view, name="lab_kdf"),
    path("lab/tamper/", lab.tamper_view, name="lab_tamper"),
]
