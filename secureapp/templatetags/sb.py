"""Small template helpers: inline icons and the people's avatars."""

from django import template
from django.urls import reverse
from django.utils.html import format_html
from django.utils.safestring import mark_safe

register = template.Library()

# 24x24 strokes, drawn to sit on the text baseline at 1.15em
ICONS = {
    "home": '<path d="M3 10.5 12 3l9 7.5V20a1 1 0 0 1-1 1h-5v-6h-6v6H4a1 1 0 0 1-1-1z"/>',
    "friends": '<circle cx="9" cy="8" r="3.5"/><path d="M2.5 20c.6-3.6 3.2-5.5 6.5-5.5s5.9 1.9 6.5 5.5"/>'
               '<path d="M16 4.8a3.3 3.3 0 0 1 0 6.4M18 14.7c2 .7 3.2 2.5 3.5 5.3"/>',
    "chat": '<path d="M4 5h16a1 1 0 0 1 1 1v10a1 1 0 0 1-1 1h-9l-5 4v-4H4a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1z"/>',
    "lab": '<path d="M9 3h6M10 3v6L4.5 18.5A1.7 1.7 0 0 0 6 21h12a1.7 1.7 0 0 0 1.5-2.5L14 9V3"/><path d="M7 15h10"/>',
    "search": '<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>',
    "globe": '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.6 3.7 5.6 3.7 9s-1.2 6.4-3.7 9c-2.5-2.6-3.7-5.6-3.7-9S9.5 5.6 12 3z"/>',
    "users": '<circle cx="9" cy="8" r="3.5"/><path d="M2.5 20c.6-3.6 3.2-5.5 6.5-5.5s5.9 1.9 6.5 5.5"/>'
             '<path d="M16 4.8a3.3 3.3 0 0 1 0 6.4M18 14.7c2 .7 3.2 2.5 3.5 5.3"/>',
    "lock": '<rect x="4.5" y="10.5" width="15" height="10.5" rx="2"/><path d="M8 10.5V7.5a4 4 0 0 1 8 0v3"/>',
    "heart": '<path d="M12 20.5s-8-4.7-8-11A4.5 4.5 0 0 1 12 7a4.5 4.5 0 0 1 8 2.5c0 6.3-8 11-8 11z"/>',
    "comment": '<path d="M20 12a8 8 0 0 1-11.6 7.1L4 20l1-4.2A8 8 0 1 1 20 12z"/>',
    "more": '<circle cx="5" cy="12" r="1.3"/><circle cx="12" cy="12" r="1.3"/><circle cx="19" cy="12" r="1.3"/>',
    "moon": '<path d="M20.5 14A8.5 8.5 0 1 1 10 3.5a7 7 0 0 0 10.5 10.5z"/>',
    "logout": '<path d="M15 4h4a1 1 0 0 1 1 1v14a1 1 0 0 1-1 1h-4M10 16l-4-4 4-4M6 12h10"/>',
    "settings": '<circle cx="12" cy="12" r="3"/><path d="M12 2.5v3M12 18.5v3M2.5 12h3M18.5 12h3M5.3 5.3l2.1 2.1M16.6 16.6l2.1 2.1M5.3 18.7l2.1-2.1M16.6 7.4l2.1-2.1"/>',
    "user": '<circle cx="12" cy="8" r="4"/><path d="M4 21c.8-4.2 4-6.5 8-6.5s7.2 2.3 8 6.5"/>',
    "shield": '<path d="M12 2.5 4.5 5.5v6c0 4.8 3.2 8.6 7.5 10 4.3-1.4 7.5-5.2 7.5-10v-6z"/><path d="m9 12 2.2 2.2L15.5 10"/>',
    "key": '<circle cx="7.5" cy="15.5" r="4"/><path d="m10.5 12.5 9-9M16 7l2.5 2.5M14 9l1.5 1.5"/>',
    "plus": '<path d="M12 5v14M5 12h14"/>',
    "check": '<path d="m5 12.5 4.5 4.5L19 7.5"/>',
    "x": '<path d="M6 6l12 12M18 6 6 18"/>',
    "send": '<path d="M21 3 10 14M21 3l-7 18-4-7-7-4z"/>',
    "back": '<path d="M15 5l-7 7 7 7"/>',
    "trash": '<path d="M4 7h16M9 7V4h6v3M6.5 7l1 13h9l1-13"/>',
    "eye": '<path d="M1.5 12S5.5 5 12 5s10.5 7 10.5 7-4 7-10.5 7S1.5 12 1.5 12z"/><circle cx="12" cy="12" r="3"/>',
    "server": '<rect x="3.5" y="4" width="17" height="7" rx="1.5"/><rect x="3.5" y="13" width="17" height="7" rx="1.5"/><path d="M7 7.5h.01M7 16.5h.01"/>',
}


@register.simple_tag
def icon(name, label=""):
    """An inline SVG. Decorative unless it is given a label."""
    aria = format_html('role="img" aria-label="{}"', label) if label else mark_safe('aria-hidden="true"')
    return format_html(
        '<svg class="i" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" '
        'stroke-linecap="round" stroke-linejoin="round" {}>{}</svg>', aria, mark_safe(ICONS[name]))


@register.simple_tag
def avatar(person, size="", link=True):
    """A round badge with a person's initials, in a colour of their own."""
    classes = "av " + size if size else "av"
    if link:
        return format_html('<a class="{}" href="{}" style="--h:{}" aria-label="{}">{}</a>',
                           classes, reverse("profile", args=[person.username]), person.hue,
                           person.name, person.initials)
    return format_html('<span class="{}" style="--h:{}" aria-hidden="true">{}</span>',
                       classes, person.hue, person.initials)


@register.filter
def first_name(person):
    return person.name.split()[0]


@register.filter
def short_ago(when):
    """5m, 3h, 2d: the chat list has no room for a sentence."""
    from django.utils import timezone
    seconds = (timezone.now() - when).total_seconds()
    if seconds < 3600:
        return f"{max(1, int(seconds // 60))}m"
    if seconds < 86400:
        return f"{int(seconds // 3600)}h"
    if seconds < 86400 * 7:
        return f"{int(seconds // 86400)}d"
    return when.strftime("%d %b")


@register.filter
def ago(when):
    """"20 hours ago", not "20 hours, 1 minute ago"."""
    from django.utils.timesince import timesince
    return timesince(when, depth=1) + " ago"
