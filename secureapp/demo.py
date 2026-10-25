PEOPLE = [
    ("nusrat", "Nusrat#2026safe", "Nusrat Jahan", "nusrat@safebook.test", "01711000001",
     "CSE at BRACU. Tea, trains, and reading the fine print."),
    ("faiaz", "Faiaz#2026safe", "Faiaz Rahman", "faiaz@safebook.test", "01711000002",
     "Breaks things to see how they were built. Mirpur."),
    ("tanvir", "Tanvir#2026safe", "Tanvir Hasan", "tanvir@safebook.test", "01711000003",
     "Photos of Old Dhaka rooftops, mostly."),
    ("mim", "Mim#2026safe", "Sadia Mim", "mim@safebook.test", "01711000004",
     "Design student. Will judge your font."),
]

ABOUT = {
    "nusrat": "Friends with everyone here. Has a post only she can read.",
    "faiaz": "Posts to friends. Waiting on a friend request from Mim.",
    "tanvir": "Shares his photos publicly. Chats with Nusrat.",
    "mim": "New here. Her friend request to Faiaz is still pending.",
}


def demo_people(accounts):
    present = {a.username: a for a in accounts.objects.filter(username__in=[p[0] for p in PEOPLE])}
    return [{"username": u, "password": pw, "name": name, "first": name.split()[0], "about": ABOUT[u],
             "initials": present[u].initials, "hue": present[u].hue}
            for u, pw, name, *_ in PEOPLE if u in present]
