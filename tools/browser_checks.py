#!/usr/bin/env python3
"""
Browser checks for SafeBook, in a real browser through Playwright.

  1. pages     every page, signed out and signed in, answers 200 with no
               console error
  2. contrast  every piece of text against WCAG AA, light and dark
  3. phone     nothing scrolls sideways at 390 px
  4. flows     a demo folder signs you in, the password eye works, a note
               can be written and found, and signing out locks the file

Start the site first on a database filled by seed_demo:

  python manage.py seed_demo
  python manage.py runserver 127.0.0.1:8010
  python tools/browser_checks.py

Uses the Edge that ships with Windows; set SB_BROWSER=chrome for Chrome.
Screenshots go to tools/shots (ignored by git).
"""
import os
import sys

from playwright.sync_api import sync_playwright

BASE = os.environ.get("SB_BASE", "http://127.0.0.1:8010")
CHANNEL = os.environ.get("SB_BROWSER", "msedge")
SHOTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "shots")
PUBLIC = ["/", "/login/", "/register/", "/recover/"]
PRIVATE = ["/", "/feed/", "/messages/", "/messages/sent/", "/messages/new/", "/people/",
           "/account/", "/posts/new/", "/lab/", "/lab/modes/", "/lab/nonce/",
           "/lab/timing/", "/lab/kdf/", "/lab/tamper/"]
PASS, FAIL = [], []


def check(name, ok, extra=""):
    (PASS if ok else FAIL).append(name)
    print(("  ok   " if ok else "  FAIL ") + name + ("  -> " + str(extra) if extra and not ok else ""))


CONTRAST_JS = r"""
() => {
  const parse = c => {
    const m = c && c.match(/rgba?\(([^)]+)\)/);
    if (!m) return null;
    const p = m[1].split(/[\s,\/]+/).filter(Boolean).map(Number);
    return {r: p[0], g: p[1], b: p[2], a: p.length > 3 ? p[3] : 1};
  };
  const lin = v => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); };
  const lum = c => 0.2126 * lin(c.r) + 0.7152 * lin(c.g) + 0.0722 * lin(c.b);
  const over = (top, under) => ({r: top.r * top.a + under.r * (1 - top.a),
                                 g: top.g * top.a + under.g * (1 - top.a),
                                 b: top.b * top.a + under.b * (1 - top.a), a: 1});
  const ratio = (a, b) => { const x = lum(a), y = lum(b); return (Math.max(x, y) + .05) / (Math.min(x, y) + .05); };
  const background = el => {
    const stack = [];
    for (let e = el; e; e = e.parentElement) {
      const c = parse(getComputedStyle(e).backgroundColor);
      if (c && c.a > 0) { stack.push(c); if (c.a >= 1) break; }
    }
    if (!stack.length || stack[stack.length - 1].a < 1) stack.push(parse(getComputedStyle(document.body).backgroundColor));
    return stack.reduceRight((acc, layer) => acc ? over(layer, acc) : layer, null);
  };
  const bad = [];
  let checked = 0;
  for (const el of document.querySelectorAll('body *')) {
    const text = [...el.childNodes].filter(n => n.nodeType === 3).map(n => n.textContent).join('').trim();
    if (!text) continue;
    const cs = getComputedStyle(el);
    const box = el.getBoundingClientRect();
    if (cs.visibility === 'hidden' || cs.display === 'none' || box.width === 0 || box.height === 0) continue;
    if (el.closest('[aria-hidden="true"], .sr-only, [hidden], option, script, style, dialog:not([open]), .redact')) continue;
    const fg = parse(cs.color);
    if (!fg) continue;
    const size = parseFloat(cs.fontSize), weight = parseInt(cs.fontWeight, 10);
    const need = (size >= 24 || (size >= 18.66 && weight >= 700)) ? 3 : 4.5;
    const bg = background(el);
    const r = ratio(fg.a < 1 ? over(fg, bg) : fg, bg);
    checked++;
    if (r < need) bad.push({text: text.slice(0, 40), ratio: Math.round(r * 100) / 100, need});
  }
  return {checked, bad};
}
"""


def open_demo(page):
    page.goto(BASE + "/login/")
    page.locator(".casefile").first.click()
    page.wait_for_load_state("networkidle")


def main():
    os.makedirs(SHOTS, exist_ok=True)
    with sync_playwright() as p:
        browser = p.chromium.launch(channel=CHANNEL)

        for theme in ("light", "dark"):
            print("\n=== %s ===" % theme)
            ctx = browser.new_context(viewport={"width": 1366, "height": 900}, color_scheme=theme)
            page = ctx.new_page()
            errors, statuses, fails, total = [], [], [], 0
            page.on("pageerror", lambda e: errors.append(str(e)))
            page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
            for stage, urls in (("out", PUBLIC), ("in", PRIVATE)):
                if stage == "in":
                    open_demo(page)
                for url in urls:
                    response = page.goto(BASE + url)
                    page.wait_for_load_state("networkidle")
                    statuses.append((url, response.status))
                    res = page.evaluate(CONTRAST_JS)
                    total += res["checked"]
                    fails += [(stage, url, b) for b in res["bad"]]
                    name = "%s-%s-%s" % (theme, stage, url.strip("/").replace("/", "-") or "home")
                    page.screenshot(path=os.path.join(SHOTS, name + ".png"), full_page=True)
            check("%s: %d pages answer 200" % (theme, len(statuses)), all(s == 200 for _, s in statuses),
                  [u for u, s in statuses if s != 200])
            check("%s: no console errors" % theme, not errors, errors[:3])
            check("%s: %d text checks pass AA" % (theme, total), not fails, fails[:6])
            ctx.close()

        print("\n=== phone ===")
        ctx = browser.new_context(viewport={"width": 390, "height": 844})
        page = ctx.new_page()
        wide = {}
        for stage, urls in (("out", PUBLIC), ("in", PRIVATE)):
            if stage == "in":
                open_demo(page)
            for url in urls:
                page.goto(BASE + url)
                page.wait_for_load_state("networkidle")
                w = page.evaluate("document.documentElement.scrollWidth")
                if w > 390:
                    wide[stage + url] = w
        check("nothing scrolls sideways at 390 px", not wide, wide)
        ctx.close()

        print("\n=== flows ===")
        ctx = browser.new_context(viewport={"width": 1366, "height": 900})
        page = ctx.new_page()
        page.goto(BASE + "/login/")
        eye = page.locator(".pw-eye").first
        eye.click()
        check("the eye shows the password", page.locator("#id_password").get_attribute("type") == "text")
        eye.click()
        check("and hides it again", page.locator("#id_password").get_attribute("type") == "password")
        open_demo(page)
        check("a demo folder opens that person's file", page.locator(".hero h1").inner_text().endswith("file"))
        page.goto(BASE + "/posts/new/")
        page.fill("#id_title", "Browser check note")
        page.fill("#id_body", "Written by the browser check.")
        page.locator("main form button[type=submit]").first.click()
        page.wait_for_load_state("networkidle")
        check("a new note opens after saving", "Browser check note" in page.content())
        page.locator("main a[href$='/delete/']").first.click()
        page.wait_for_load_state("networkidle")
        confirm = page.locator("main form button[type=submit]").last
        confirm.click()
        page.wait_for_load_state("networkidle")
        check("and can be deleted again", "Browser check note" not in page.content())
        page.locator("#signOut button").click()
        page.wait_for_load_state("networkidle")
        page.goto(BASE + "/account/")
        check("signing out locks the file", "/login/" in page.url)
        ctx.close()

        browser.close()
    print("\n%d passed, %d failed" % (len(PASS), len(FAIL)))
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
