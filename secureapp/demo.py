PEOPLE = [
    ("maliha", "Maliha#2026safe", "Maliha Haque", "maliha@safebook.test", "01711000001",
     "CSE at BRACU. Tea, trains, and reading the fine print."),
    ("rehan", "Rehan#2026safe", "Rehan Siddiqui", "rehan@safebook.test", "01711000002",
     "Breaks things to see how they were built. Mirpur."),
    ("sajid", "Sajid#2026safe", "Sajid Mahmud", "sajid@safebook.test", "01711000003",
     "Photos of Old Dhaka rooftops, mostly."),
    ("oishee", "Oishee#2026safe", "Oishee Barua", "oishee@safebook.test", "01711000004",
     "Design student. Will judge your font."),
]

ABOUT = {
    "maliha": "Friends with everyone here. Has a post only she can read.",
    "rehan": "Posts to friends. Waiting on a friend request from Oishee.",
    "sajid": "Shares his photos publicly. Chats with Maliha.",
    "oishee": "New here. Her friend request to Rehan is still pending.",
}


def demo_people(accounts):
    present = {a.username: a for a in accounts.objects.filter(username__in=[p[0] for p in PEOPLE])}
    return [{"username": u, "password": pw, "name": name, "first": name.split()[0], "about": ABOUT[u],
             "initials": present[u].initials, "hue": present[u].hue}
            for u, pw, name, *_ in PEOPLE if u in present]
