"""Photos on posts.

A photo is opened with Pillow and saved again, smaller, which drops the EXIF
block (camera, time, GPS) and any other metadata. The clean copy is then
sealed with the post's own key in keyring.py, so whoever can read the post
can see the photo and nobody else can.
"""
import io

from PIL import Image, ImageOps, UnidentifiedImageError

MAX_BYTES = 4 * 1024 * 1024
MAX_SIDE = 1600
ALLOWED = {"JPEG", "PNG", "WEBP"}


class PhotoError(ValueError):
    pass


def clean_photo(upload):
    """(bytes, content type) of a resized copy with no metadata in it."""
    if upload.size > MAX_BYTES:
        raise PhotoError("Photos can be up to 4 MB.")
    try:
        img = Image.open(upload)
        kind = img.format
        img.load()
    except (UnidentifiedImageError, OSError):
        raise PhotoError("That file is not a photo SafeBook can use. Try a JPEG, PNG or WebP.")
    if kind not in ALLOWED:
        raise PhotoError("Use a JPEG, PNG or WebP photo.")

    # turn it the right way up before the EXIF orientation tag is thrown away
    img = ImageOps.exif_transpose(img)
    img.thumbnail((MAX_SIDE, MAX_SIDE))
    out = io.BytesIO()
    if kind == "PNG":
        img.save(out, "PNG")
        return out.getvalue(), "image/png"
    img.convert("RGB").save(out, "JPEG", quality=85)
    return out.getvalue(), "image/jpeg"
