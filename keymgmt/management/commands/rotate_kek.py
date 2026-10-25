"""Replace the server KEK without re-encrypting a single post.

Each public post carries its content key wrapped under the KEK. Rotating
means unwrapping that 32 byte key with the old KEK and wrapping it again
with the new one. The post's own ciphertext is never read and never
rewritten, which is the reason for wrapping keys inside keys in the first
place.

Only-me and friends posts hold no server-wrapped key at all, so there is
nothing here for the server to rotate - and nothing for it to read either.
"""
import base64

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from keymgmt.services import VALID_KEY_SIZES, get_active_kek
from secureapp.crypto import unwrap_key, wrap_key
from secureapp.keys import AAD_POST_KEY_PUBLIC
from secureapp.models import Post


class Command(BaseCommand):
    help = "Re-wrap every public post key from the current KEK to a new one."

    def add_arguments(self, parser):
        parser.add_argument("--new-kek-b64", required=True,
                            help="the replacement KEK, base64 encoded")
        parser.add_argument("--new-kek-id", type=int, required=True,
                            help="the id to record against the re-wrapped keys")
        parser.add_argument("--dry-run", action="store_true",
                            help="report what would change and write nothing")

    def handle(self, *args, **options):
        try:
            new_kek = base64.b64decode(options["new_kek_b64"], validate=True)
        except Exception as exc:
            raise CommandError(f"--new-kek-b64 is not valid base64: {exc}")
        if len(new_kek) not in VALID_KEY_SIZES:
            raise CommandError(
                f"the new KEK decodes to {len(new_kek)} bytes; AES needs 16, 24 or 32."
            )

        old_kek, old_id = get_active_kek()
        new_id = options["new_kek_id"]
        if new_kek == old_kek:
            raise CommandError("the new KEK is the same as the current one.")

        rows = Post.objects.filter(audience=Post.PUBLIC).exclude(key_public=None)
        done = 0

        with transaction.atomic():
            for post in rows:
                try:
                    post_key = unwrap_key(post.key_public, old_kek, AAD_POST_KEY_PUBLIC)
                except Exception:
                    raise CommandError(
                        f"post {post.id} does not open with the current KEK. "
                        "Check KEYMGMT_ACTIVE_KEK_ID matches APP_KEK_BASE64 before rotating."
                    )
                if not options["dry_run"]:
                    post.key_public = wrap_key(post_key, new_kek, AAD_POST_KEY_PUBLIC)
                    post.key_public_kek_id = new_id
                    post.save(update_fields=["key_public", "key_public_kek_id"])
                done += 1

            if options["dry_run"]:
                transaction.set_rollback(True)

        verb = "would re-wrap" if options["dry_run"] else "re-wrapped"
        self.stdout.write(self.style.SUCCESS(
            f"{verb} {done} public post keys from KEK {old_id} to KEK {new_id}."
        ))
        if not options["dry_run"]:
            self.stdout.write(self.style.WARNING(
                "Now update .env: APP_KEK_BASE64 to the new key and "
                f"KEYMGMT_ACTIVE_KEK_ID to {new_id}. Until you do, the feed "
                "cannot open any of these posts."
            ))
