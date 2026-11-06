# Flag 6 — Confused Deputy via Intent Forwarding (through Flag5)

**Vulnerability category:** Intent redirection / confused deputy
**Target components:** `io.hextree.attacksurface.activities.Flag5Activity` (exported, used as a forwarder), `io.hextree.attacksurface.activities.Flag6Activity` (reached indirectly)

---

## Target

This flag isn't reached directly — it builds on the nested-intent behavior from [flag 5](../flag-5). `Flag5Activity` doesn't just read the extras of the `Intent` nested inside it: when the nested intent's `reason` extra is set to `"next"`, `Flag5Activity` takes the `nextIntent` extra it finds and **forwards it itself**, calling `startActivity()` on it. In other words, `Flag5Activity` acts as a relay that launches whatever `Intent` an attacker hands it.

`Flag6Activity` then checks a flag/bit on the `Intent` it receives (set via `FLAG_GRANT_READ_URI_PERMISSION` in this PoC) before releasing its flag.

## Vulnerability

`Flag5Activity` is a textbook **confused deputy**: it has the ability to start other activities (including ones that might not be reachable, or might behave differently, when launched directly), and it does so using an `Intent` object it received as untrusted input, without validating or restricting where that intent can point or what flags it carries.

Because the forwarded intent is built entirely by the attacker and simply passed through `Flag5Activity.startActivity()`, two things happen:

1. The attacker gets to choose the target of the forwarded intent (`Flag6Activity` here, but nothing stops it from being any other exported — or even non-exported, depending on internal checks — component).
2. The attacker controls every flag and extra set on that forwarded intent, including flags like `FLAG_GRANT_READ_URI_PERMISSION` that `Flag6Activity`'s logic happens to check for.

So instead of needing to find a way to set that bit while talking to `Flag6Activity` directly, the attacker just builds the already-correct `Intent` up front and lets `Flag5Activity` be the one that calls `startActivity()` on it.

## Approach

This reuses the same nested-intent structure as flag 5, with one more layer:

```kotlin
// Intent actually addressed to Flag6Activity, with the flag its check expects.
val toFlag6 = Intent().apply {
    setClassName(TARGET, "$TARGET.activities.Flag6Activity")
    putExtra("reason", "next")                           // tells Flag5 to forward instead of just reading extras
    addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)       // the bit Flag6Activity checks for
}

// Middle intent: return=42 (satisfies Flag5's own check) + the intent to forward.
val inner = Intent().apply {
    putExtra("return", 42)
    putExtra("nextIntent", toFlag6)
}

// Outer intent: addressed to Flag5Activity, which will read "inner" and,
// seeing reason == "next", forward toFlag6 via its own startActivity() call.
val outer = Intent().apply {
    setClassName(TARGET, "$TARGET.activities.Flag5Activity")
    putExtra(Intent.EXTRA_INTENT, inner)
}

startActivity(outer)
```

1. Decompile and confirm that `Flag5Activity` forwards (`startActivity()`) rather than just inspects the nested intent when `reason == "next"`.
2. Decompile `Flag6Activity` to find the exact flag/extra it checks for before releasing its flag.
3. Build the three-layer intent above from a launcher app and fire it at `Flag5Activity`. `Flag5Activity` does the actual forwarding, landing the attacker-crafted intent at `Flag6Activity`.

See [`exploit/MainActivity.kt`](./exploit/MainActivity.kt) for the full launcher code used.

## Why it works

`Flag5Activity` has privileges (the ability to call `startActivity()` with an arbitrary intent) that the attacker doesn't have reason to be granted directly, and it exercises those privileges on behalf of whatever intent it was handed — without checking that the intent's destination or flags are something it's actually supposed to forward. This is the classic confused-deputy pattern: a component with more capability than the caller ends up using that capability *for* the caller, because it trusts data it should instead be treating as untrusted input.

## Fix

- **Never forward an attacker-controlled `Intent` via `startActivity()`/`startActivityForResult()` without restricting it first.** At minimum, validate the target component (package + class) against an allow-list, and strip flags/extras that weren't explicitly meant to be passed through.
- If forwarding is a legitimate feature, use `Intent.setClassName()`/explicit resolution with a fixed, hardcoded target rather than trusting whatever component name arrives inside the nested intent.
- Apply the same lesson as flag 5: an `Intent` nested inside another `Intent` is just attacker-supplied data at every layer. A component that unwraps and *acts on* that data (here, by launching it) inherits all of the attacker's control over it.
