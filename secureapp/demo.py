"""The demo accounts, in one place.

seed_demo builds them and the sign in page offers them as case files, so a
visitor can look around without making an account. Their passwords are in the
README too; these are throwaway accounts on a demo database, never real ones.
"""

PEOPLE = [
    ("nusrat", "Nusrat#2026safe", "nusrat@safebook.test", "01711000001"),
    ("faiaz", "Faiaz#2026safe", "faiaz@safebook.test", "01711000002"),
    ("tanvir", "Tanvir#2026safe", "tanvir@safebook.test", "01711000003"),
]

# what each file holds, for the label on the folder
ABOUT = {
    "nusrat": "Two notes, one shared. Messages waiting, one of them anonymous.",
    "faiaz": "Keeps bank details private. Writes about scrypt in the open.",
    "tanvir": "Ran the padlock through the lab. Sent a note without a name.",
}


def demo_files(accounts):
    """The demo people who exist in this database, ready for the folders."""
    present = set(accounts.objects.filter(username__in=[p[0] for p in PEOPLE])
                  .values_list("username", flat=True))
    return [{"username": u, "password": pw, "about": ABOUT[u], "ref": "%03d" % (i + 1)}
            for i, (u, pw, _, _) in enumerate(PEOPLE) if u in present]
