import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


def drop_old_rows(apps, schema_editor):
    apps.get_model("secureapp", "Post").objects.all().delete()
    apps.get_model("secureapp", "Message").objects.all().delete()


class Migration(migrations.Migration):

    dependencies = [
        ("secureapp", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="account",
            name="display_name",
            field=models.CharField(blank=True, max_length=60),
        ),
        migrations.AddField(
            model_name="account",
            name="bio",
            field=models.CharField(blank=True, max_length=160),
        ),
        migrations.AddField(
            model_name="post",
            name="audience",
            field=models.CharField(choices=[("me", "Only me"), ("friends", "Friends"), ("public", "Public")],
                                   default="friends", max_length=10),
        ),
        migrations.RunPython(drop_old_rows, migrations.RunPython.noop),
        migrations.RemoveField(model_name="post", name="is_public"),
        migrations.RemoveField(model_name="post", name="title_ct"),
        migrations.RemoveField(model_name="post", name="title_nonce"),
        migrations.RemoveField(model_name="message", name="is_anonymous"),
        migrations.RemoveField(model_name="message", name="title_ct"),
        migrations.RemoveField(model_name="message", name="title_nonce"),
        migrations.AlterField(
            model_name="message",
            name="sender",
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE,
                                    related_name="sent_messages", to=settings.AUTH_USER_MODEL),
        ),
        migrations.AlterField(
            model_name="message",
            name="key_for_sender",
            field=models.BinaryField(),
        ),
        migrations.AlterModelOptions(name="message", options={"ordering": ["created_at"]}),
        migrations.CreateModel(
            name="FriendRequest",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("accepted_at", models.DateTimeField(blank=True, null=True)),
                ("from_user", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE,
                                                related_name="requests_sent", to=settings.AUTH_USER_MODEL)),
                ("to_user", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE,
                                              related_name="requests_received", to=settings.AUTH_USER_MODEL)),
            ],
            options={
                "constraints": [models.UniqueConstraint(fields=("from_user", "to_user"), name="one_request_each_way")],
            },
        ),
        migrations.CreateModel(
            name="PostShare",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("wrapped_key", models.BinaryField()),
                ("post", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE,
                                           related_name="shares", to="secureapp.post")),
                ("reader", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE,
                                             related_name="shared_with_me", to=settings.AUTH_USER_MODEL)),
            ],
            options={
                "constraints": [models.UniqueConstraint(fields=("post", "reader"), name="one_share_per_reader")],
            },
        ),
        migrations.CreateModel(
            name="Comment",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("body_ct", models.BinaryField()),
                ("body_nonce", models.BinaryField()),
                ("mac", models.BinaryField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("author", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE,
                                             to=settings.AUTH_USER_MODEL)),
                ("post", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE,
                                           related_name="comments", to="secureapp.post")),
            ],
            options={"ordering": ["created_at"]},
        ),
        migrations.CreateModel(
            name="Like",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("post", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE,
                                           related_name="likes", to="secureapp.post")),
                ("user", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE,
                                           to=settings.AUTH_USER_MODEL)),
            ],
            options={
                "constraints": [models.UniqueConstraint(fields=("post", "user"), name="one_like_each")],
            },
        ),
    ]
