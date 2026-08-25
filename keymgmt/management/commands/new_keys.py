import base64
import os

from django.core.management.base import BaseCommand
from django.core.management.utils import get_random_secret_key


class Command(BaseCommand):
    help = "Print a fresh SECRET_KEY and APP_KEK_BASE64 for a new .env."

    def handle(self, *args, **options):
        self.stdout.write("SECRET_KEY=" + get_random_secret_key())
        self.stdout.write("APP_KEK_BASE64=" + base64.b64encode(os.urandom(32)).decode())
        self.stdout.write("KEYMGMT_ACTIVE_KEK_ID=1")
        self.stdout.write(self.style.WARNING(
            "\nPaste these into .env. Changing APP_KEK_BASE64 on a database that "
            "already has public posts needs `rotate_kek`, not a hand edit."
        ))
