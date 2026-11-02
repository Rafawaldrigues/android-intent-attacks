# Flag 5 — Nested Intents ("Intent-in-Intent" / Matryoshka Attack)

**Vulnerability category:** Intent redirection
**Target component:** `io.hextree.attacksurface.activities.Flag5Activity` (exported)

---

## Target

An exported `Activity` that doesn't just read its own `Intent`'s extras — it also unwraps an `Intent` embedded *inside* another `Intent`'s extras (via `Intent.EXTRA_INTENT` / `"android.intent.extra.INTENT"`), and that nested intent in turn carries its own extras, which must match specific expected values before the activity releases the flag.

## Vulnerability

Android lets an `Intent` carry another `Intent` as a `Parcelable` extra. Some apps use this pattern legitimately (e.g. "open this screen, then forward this intent once done"), but when the checks on the nested intent's content are not tied to who actually sent the outer intent, the whole chain is just attacker-controlled data — nesting it a level deeper doesn't add any trust.

In this challenge, `Flag5Activity` expects:

- An outer intent addressed to it directly, carrying an `Intent` under the `EXTRA_INTENT` key.
- That inner intent must carry specific extras (e.g. a numeric `return` value) that the activity's logic checks.
- The inner intent itself can carry *another* nested `Intent` (e.g. under a custom key like `nextIntent`), with its own expected extra (e.g. a `reason` string), continuing the chain.

Since every layer of this "matryoshka doll" of intents is just a `Bundle`/`Parcelable` built by whoever constructs the outer `Intent`, an attacker who can launch the exported activity directly can supply the entire nested structure at once — there's no actual IPC round-trip or external validation happening per layer, it's all just Intent extras.

## Approach

1. Decompile the target APK and trace through `Flag5Activity`'s code to see:
   - Which key it reads the nested intent from (`EXTRA_INTENT`).
   - Which extras it expects at each level, and their exact expected values.
2. Build the nested structure from the inside out, in a small launcher app:
   - Innermost intent: just the extra(s) expected at the deepest level (e.g. `reason = "back"`).
   - Middle intent: the extra expected at that level (e.g. `return = 42`), plus the innermost intent attached under its own extra key (`nextIntent`).
   - Outer intent: addressed explicitly to `Flag5Activity` via `setClassName`, carrying the middle intent under `android.intent.extra.INTENT`.
3. Fire the outer intent with `startActivity()` and read the result from logs (or, if the activity returns data, via `onActivityResult`).

```kotlin
// innermost intent — reason = "back"
val nextIntent = Intent().apply {
    putExtra("reason", "back")
}

// middle intent — return = 42, carries the innermost intent
val inner = Intent().apply {
    putExtra("return", 42)
    putExtra("nextIntent", nextIntent)
}

// outer intent — addressed to Flag5Activity, carries "inner" as EXTRA_INTENT
val outer = Intent().apply {
    setClassName(TARGET, "$TARGET.activities.Flag5Activity")
    putExtra(Intent.EXTRA_INTENT, inner)
}

startActivity(outer)
```

See [`exploit/MainActivity.kt`](./exploit/MainActivity.kt) for the full launcher used, including logging of the assembled intent and of whatever comes back in `onActivityResult`.

## Why it works

Wrapping an `Intent` inside another `Intent` doesn't create a trust boundary — both are just data structures the caller fully controls. If the activity's validation logic treats "I found an `Intent` under this extra key with these values" as equivalent to "this request legitimately passed through the expected multi-step flow," an attacker can simply hand-build the whole nested structure in one shot and skip straight to satisfying every check at once.

## Fix

- Never treat a nested `Intent` extra as a trusted message from another component just because it has the right shape. Validate the actual caller (`getCallingPackage()`, a signature-level permission) before acting on any extras, nested or not.
- If a flow is genuinely meant to be multi-step, drive it through internal state tied to a real session/backend check, not through data the client assembled and handed over in one `Intent`.
- Treat `Intent.EXTRA_INTENT` (and any custom "intent inside an intent" pattern) as a red flag during review — it's a common vector for intent redirection and confused-deputy issues.
