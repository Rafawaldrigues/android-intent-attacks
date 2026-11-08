# Flag 13 — Forging a Browser-Originated Deep Link

**Vulnerability category:** Deep link / App Link trust bypass
**Target component:** `io.hextree.attacksurface.activities.Flag13Activity` (exported)

---

## Target

`Flag13Activity` is meant to be reached through a `hex://` deep link opened from a real browser (Chrome). Before trusting the link's data, it runs a check meant to confirm the intent actually came from a browser:

```java
private boolean isDeeplink(Intent intent) {
    String action;
    return (intent == null
            || (action = intent.getAction()) == null
            || !action.equals("android.intent.action.VIEW")
            || !intent.getCategories().contains("android.intent.category.BROWSABLE")
            || intent.getStringExtra("com.android.browser.application_id") == null)
        ? false : true;
}

protected void onCreate(Bundle bundle) {
    super.onCreate(bundle);
    this.f = new LogHelper(this);
    Intent intent = getIntent();
    if (intent == null) {
        finish();
    }
    if (isDeeplink(intent)) {
        Uri data = intent.getData();
        if (data.getHost().equals("flag") && data.getQueryParameter("action").equals("give-me")) {
            success(this);
            return;
        }
        // ... handles hex://open?message=... for a (benign) different flow
    }
    // falls through to opening a web page that would normally produce a proper deep link
}
```

If `isDeeplink()` returns true and the URI is `hex://flag?action=give-me`, the flag is released immediately.

## Vulnerability

`isDeeplink()` tries to distinguish "this intent genuinely came from a browser following a link" from "this intent was crafted directly," but every signal it checks is just **data carried on the `Intent` itself** — fully attacker-controlled when the activity is exported:

- `action == ACTION_VIEW` — any caller can set this.
- `category` contains `BROWSABLE` — any caller can add this category.
- The extra `"com.android.browser.application_id"` is non-null — this is a real convention Chrome (and other browsers) use to identify which app initiated a Custom Tab / browser session, but it's just a string extra. Nothing stops any other caller from setting the exact same key with any value, including `"com.android.chrome"`.

None of these three checks involve anything the OS actually enforces (like verifying the real calling package, or going through Android App Link / `autoVerify` domain verification). They're a heuristic for "this looks like it came from a browser," and a heuristic built entirely out of caller-suppliable data provides no real guarantee.

## Approach

Fire the deep link directly via `adb`, setting the same three signals `isDeeplink()` checks for:

```bash
adb shell am start -a android.intent.action.VIEW \
  -c android.intent.category.BROWSABLE \
  -d "hex://flag?action=give-me" \
  --es com.android.browser.application_id com.android.chrome
```

- `-a android.intent.action.VIEW` — satisfies the action check.
- `-c android.intent.category.BROWSABLE` — satisfies the category check.
- `-d "hex://flag?action=give-me"` — the URI the activity's success branch checks for (`host == "flag"`, `action=give-me`).
- `--es com.android.browser.application_id com.android.chrome` — forges the "came from Chrome" extra.

No PoC app is needed — the intent is built and delivered directly from the command line, and `isDeeplink()` has no way to tell this apart from a real browser-originated link.

## Why it works

The check conflates *values a real browser conventionally sets* with *proof that a real browser set them*. Since `Flag13Activity` is exported and reachable by an arbitrary `ACTION_VIEW` intent, any caller — an app, or `adb` directly — can replicate every one of those values without ever going through an actual browser or a verified App Link.

## Fix

- Don't infer "this came from a trusted browser" from action/category/extra values alone — none of them are enforced by the OS and all are attacker-settable on an exported component.
- Use Android App Links with `android:autoVerify="true"` and a verified domain association (`assetlinks.json`) if the goal is to only accept links that were resolved through real domain ownership verification — and remember that even then, an explicitly-addressed intent from another app bypasses verification entirely (see [flag 3](../flag-3)), so this alone isn't sufficient if the component must also stay closed to direct intents.
- If an action is sensitive (like releasing a flag/secret), it shouldn't be reachable this easily regardless of claimed origin — gate it behind real user interaction confirmed by the app itself, or a server-side check, rather than trusting intent metadata.
