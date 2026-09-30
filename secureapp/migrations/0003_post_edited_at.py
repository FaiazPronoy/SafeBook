from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("secureapp", "0002_social_network"),
    ]

    operations = [
        migrations.AddField(
            model_name="post",
            name="edited_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
