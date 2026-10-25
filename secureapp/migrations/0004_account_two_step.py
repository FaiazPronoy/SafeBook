from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("secureapp", "0003_post_edited_at"),
    ]

    operations = [
        migrations.AddField(
            model_name="account",
            name="two_step",
            field=models.BooleanField(default=False),
        ),
    ]
