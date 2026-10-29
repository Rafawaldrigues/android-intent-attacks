# Flag 3 — Deep Link / App Link Trust Bypass via Explicit Intent

## Challenge summary

The target app exposes an `Activity` (`Flag3Activity`) that is meant to be reached through a deep link / App Link: it expects an `Intent` carrying a specific `https://` URI (e.g. a link under the app's own domain) as the `data` field, and hands out the flag once it sees that URI.

Normally this activity would only be reachable by tapping a link that the OS resolves to the app (via an `<intent-filter>` with `android:autoVerify="true"` and the matching host, or just a registered scheme/host). That resolution step is exactly what a malicious app can skip.

## Vulnerability

- `Flag3Activity` is exported and declares an `<intent-filter>` for a specific `https` host, used for Android App Links.
- The activity's logic trusts the `Intent.data` URI as proof that the user actually navigated through the expected web link.
- Because the activity is exported, any other installed app can build the **exact same `Intent`** directly — using an **explicit** intent (`setClassName`) instead of an implicit one — and set `data` to whatever URI the activity expects, without ever going through link verification, a browser, or user interaction with a real link.

In other words, the "deep link" check is really just "does `Intent.data` equal this value?", and that check can be satisfied by any app, not only by the OS's link-resolution flow. App Link / deep-link data should never be treated as proof of origin on its own.

## Approach

1. Decompile the target APK and locate `Flag3Activity`'s code to find the exact `data` URI (and action) it expects before releasing the flag.
2. From a separate launcher app, build an explicit `Intent`:
   - `setClassName(targetPackage, targetPackage + ".activities.Flag3Activity")`
   - `action = "io.hextree.action.GIVE_FLAG"`
   - `data = Uri.parse("https://app.hextree.io/map/android")` — the URI the activity checks for.
3. Call `startActivity()` on that intent from the launcher app.
4. Install both apps, launch the launcher, and read the flag from the target activity's output (`adb logcat`).

Since the intent is explicit, Android delivers it straight to `Flag3Activity` regardless of the app's declared `<intent-filter>` / App Link verification — those only matter for *implicit* intents coming from outside sources like a browser.

See [`exploit/MainActivity.kt`](./exploit/MainActivity.kt) for the launcher code used.

## Fix

- Never use the mere presence of a specific `Intent.data` value as a security or identity check — it is fully attacker-controlled once the component is exported.
- If the activity must stay exported for legitimate App Link use, verify the actual calling context (e.g. `getCallingPackage()`, checking that the intent arrived via `ACTION_VIEW` from a genuine browser/launcher flow) or move the sensitive logic behind a non-exported component that the deep-link activity hands off to only after validating the caller.
- Treat deep links as a *routing* mechanism, not an *authentication* mechanism.
