import base64
import os

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.core.management.utils import get_random_secret_key

PLACEHOLDER = "put-32-random-bytes-base64-encoded-here"


class Command(BaseCommand):
    help = "Print a fresh SECRET_KEY and APP_KEK_BASE64, or write them into .env."

    def add_arguments(self, parser):
        parser.add_argument("--write", action="store_true",
                            help="put the new keys into .env, which must still hold "
                                 "the placeholders from .env.example")

    def handle(self, *args, **options):
        secret = get_random_secret_key()
        kek = base64.b64encode(os.urandom(32)).decode()

        if options["write"]:
            path = settings.BASE_DIR / ".env"
            text = path.read_text(encoding="utf-8") if path.exists() else ""
            # a real KEK already in .env opens every public post; replacing it
            # by accident would lock them all, so this only fills placeholders
            if PLACEHOLDER not in text:
                raise CommandError(".env already has keys. Use rotate_kek to change the KEK.")
            lines = []
            for line in text.splitlines():
                if line.startswith("SECRET_KEY="):
                    line = "SECRET_KEY=" + secret
                elif line.startswith("APP_KEK_BASE64="):
                    line = "APP_KEK_BASE64=" + kek
                lines.append(line)
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            self.stdout.write(self.style.SUCCESS("Wrote a fresh SECRET_KEY and APP_KEK_BASE64 into .env."))
            return

        self.stdout.write("SECRET_KEY=" + secret)
        self.stdout.write("APP_KEK_BASE64=" + kek)
        self.stdout.write("KEYMGMT_ACTIVE_KEK_ID=1")
        self.stdout.write(self.style.WARNING(
            "\nPaste these into .env, or run new_keys --write to do it for you. Changing "
            "APP_KEK_BASE64 on a database that already has public posts needs "
            "`rotate_kek`, not a hand edit."
        ))
