from django.urls import path

from . import lab, views

urlpatterns = [
    path("", views.home_view, name="index"),
    path("feed/", views.feed_view, name="feed"),
    path("people/", views.directory_view, name="directory"),

    path("register/", views.register_view, name="register"),
    path("register/recovery-code/", views.recovery_code_view, name="recovery_code"),
    path("login/", views.login_view, name="login"),
    path("logout/", views.logout_view, name="logout"),
    path("recover/", views.recover_view, name="recover"),

    path("account/", views.account_view, name="account"),
    path("account/password/", views.change_password_view, name="change_password"),

    path("posts/new/", views.post_new_view, name="post_new"),
    path("posts/<int:post_id>/", views.post_detail_view, name="post_detail"),
    path("posts/<int:post_id>/visibility/", views.post_visibility_view, name="post_visibility"),
    path("posts/<int:post_id>/delete/", views.post_delete_view, name="post_delete"),

    path("messages/", views.messages_inbox_view, name="messages_inbox"),
    path("messages/sent/", views.messages_sent_view, name="messages_sent"),
    path("messages/new/", views.message_new_view, name="message_new"),
    path("messages/new/<str:to>/", views.message_new_view, name="message_to"),
    path("messages/<int:msg_id>/", views.message_detail_view, name="message_detail"),

    path("lab/", lab.lab_index, name="lab"),
    path("lab/modes/", lab.modes_view, name="lab_modes"),
    path("lab/nonce/", lab.nonce_view, name="lab_nonce"),
    path("lab/timing/", lab.timing_view, name="lab_timing"),
    path("lab/kdf/", lab.kdf_view, name="lab_kdf"),
    path("lab/tamper/", lab.tamper_view, name="lab_tamper"),
]
