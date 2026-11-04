import io

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from PIL import Image

from secureapp.models import Post

from .test_confidentiality import full_account, sign_in
from .test_social import befriend


def jpeg_with_exif():
    img = Image.new("RGB", (40, 30), (200, 80, 40))
    exif = Image.Exif()
    exif[0x010F] = "PhoneMaker"          # camera make
    out = io.BytesIO()
    img.save(out, "JPEG", exif=exif)
    return SimpleUploadedFile("trip.jpg", out.getvalue(), content_type="image/jpeg")


class PhotoTests(TestCase):
    def setUp(self):
        self.alice, _, _ = full_account("alice")
        self.bob, _, _ = full_account("bob")
        self.carol, _, _ = full_account("carol")
        befriend(self.alice, self.bob)
        sign_in("alice").post("/posts/new/", {"body": "rooftop", "audience": "friends",
                                              "photo": jpeg_with_exif()})
        self.post = Post.objects.get()
        self.url = f"/posts/{self.post.id}/photo/"

    def test_the_stored_bytes_are_not_an_image(self):
        stored = bytes(self.post.image_ct)
        self.assertFalse(stored.startswith(b"\xff\xd8"))
        with self.assertRaises(Exception):
            Image.open(io.BytesIO(stored))

    def test_a_friend_sees_it_and_the_exif_is_gone(self):
        response = sign_in("bob").get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "image/jpeg")
        img = Image.open(io.BytesIO(response.content))
        self.assertNotIn(0x010F, img.getexif())

    def test_a_stranger_gets_nothing(self):
        self.assertEqual(sign_in("carol").get(self.url).status_code, 404)

    def test_signed_out_gets_nothing(self):
        self.assertNotEqual(self.client.get(self.url).status_code, 200)

    def test_moving_it_to_only_me_hides_the_photo_from_the_friend(self):
        sign_in("alice").post(f"/posts/{self.post.id}/audience/", {"audience": "me"})
        self.assertEqual(sign_in("bob").get(self.url).status_code, 404)

    def test_a_public_photo_opens_for_any_signed_in_person(self):
        sign_in("alice").post(f"/posts/{self.post.id}/audience/", {"audience": "public"})
        self.assertEqual(sign_in("carol").get(self.url).status_code, 200)

    def test_a_file_that_is_not_a_photo_is_refused(self):
        bad = SimpleUploadedFile("notes.jpg", b"not really a jpeg", content_type="image/jpeg")
        sign_in("alice").post("/posts/new/", {"body": "second", "audience": "me", "photo": bad})
        self.assertEqual(Post.objects.count(), 1)
