# Flag 10 — Implicit Intent Hijacking

**Vulnerability category:** Implicit intent resolution / hijacking
**Target behavior:** `io.hextree.attacksurface` sends an implicit intent with action `io.hextree.attacksurface.ATTACK_ME`, meant for one of its own components

---

## Target

The target app, at some point in its own flow, fires an implicit `Intent` — addressed only by `action` (`io.hextree.attacksurface.ATTACK_ME`), with no explicit package/class set — carrying the flag as a string extra. It presumably expects Android to resolve that intent back to a component of its own.

Because the intent is implicit, Android doesn't deliver it to a specific app: it resolves it against **every installed app's declared `<intent-filter>`s** and lets the matching component handle it (prompting the user to choose, if more than one app matches, or delivering it directly if the target app registers the only — or the highest-priority — match).

## Vulnerability

Any installed app can register an `<intent-filter>` for the same `action` (and `category`) the target app uses internally, and become a valid candidate to receive that intent — including its extras, like the flag. This works because:

- The sending app never specified an explicit destination (no `setClassName()` / `setPackage()`), so there's nothing restricting resolution to the sender's own app.
- The action string (`io.hextree.attacksurface.ATTACK_ME`) isn't itself a secret — it only needs to be guessed or recovered from the decompiled app, then declared in another app's manifest.
- There's no signature-level permission or `android:exported="false"` guarding whichever internal component was supposed to receive this intent, so a third-party `<intent-filter>` match is accepted exactly like the legitimate one would be.

This is the counterpart to exported-component issues: there, an attacker reaches into the target app directly; here, the **target app itself** reaches out with data, trusting implicit resolution to land it somewhere safe — and a malicious app simply positions itself to catch it instead.

## Approach

1. Decompile the target app and find the custom action string used for this internal implicit intent (`io.hextree.attacksurface.ATTACK_ME`), along with the category it's sent with (`DEFAULT`).
2. Declare an exported activity in a PoC app with a matching `<intent-filter>`:

```xml
<activity android:name=".CatcherActivity" android:exported="true">
    <intent-filter>
        <action android:name="io.hextree.attacksurface.ATTACK_ME"/>
        <category android:name="android.intent.category.DEFAULT"/>
    </intent-filter>
</activity>
```

3. Implement that activity to simply read whatever extra the flag arrives in:

```kotlin
class CatcherActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val flag = intent.getStringExtra("flag")
        // ... use the flag
    }
}
```

4. Install the PoC app, trigger whatever flow in the target app fires this implicit intent, and let Android's resolution deliver it to `CatcherActivity` instead of (or alongside) the target's own intended recipient.

See [`exploit/CatcherActivity.kt`](./exploit/CatcherActivity.kt) and [`exploit/AndroidManifest.xml`](./exploit/AndroidManifest.xml) for the full PoC used.

## Why it works

Implicit intent resolution is, by design, open to every installed app that declares a matching filter — that's the whole point of the mechanism (letting the user pick a handler, letting third-party apps integrate). The vulnerability isn't in Android's resolution behavior; it's in using an implicit intent at all to deliver sensitive data (like a flag/secret) to a component that was only ever meant to be reached from inside the same app. Once the data leaves the sending app addressed only by action/category, the receiving app has no way to control who shows up to claim it.

## Fix

- **Use an explicit intent** (`setClassName()` / `setPackage()`) whenever the sender and receiver are both known ahead of time and belong to the same app (or a specific trusted app) — this is almost always the right choice for internal communication.
- If an implicit intent is genuinely required (e.g. letting the user pick among several apps), never put sensitive data directly in it. Use a different channel to actually transfer the secret once a specific, verified component has been chosen.
- Where the receiving component must stay reachable by action/category, protect it with a signature-level permission so only apps signed by the same key can register a matching filter that Android will actually honor.
