# Flag 12 — An Extra Condition That Adds No Real Security

**Vulnerability category:** Implicit intent hijacking + exported component trusting its own incoming extras
**Target component:** `io.hextree.attacksurface.activities.Flag12Activity`

---

## Target

Nearly identical to [flag 11](../flag-11): `Flag12Activity` sends the same implicit `Intent` (`io.hextree.attacksurface.ATTACK_ME`) via `startActivityForResult()` and checks for the same `"token" == 1094795585` result. The difference — and the actual point of this challenge ("Careful intent conditions") — is an extra guard before accepting the result:

```java
protected void onActivityResult(int i, int i2, Intent intent) {
    super.onActivityResult(i, i2, intent);
    if (intent == null || getIntent() == null || !getIntent().getBooleanExtra("LOGIN", false)) {
        return;
    }
    this.f.addTag("LOGIN");
    if (intent.getIntExtra("token", -1) == 1094795585) {
        this.f.addTag(1094795585);
        success(this);
    }
}
```

The flag is only released if **both** are true:
1. The result `Intent` carries `"token" == 1094795585`, and
2. The `Intent` that originally launched `Flag12Activity` itself carries a boolean extra `"LOGIN" == true`.

## Vulnerability

The second condition looks like it adds a real precondition (perhaps intended to represent "the user actually went through a login flow before this screen"), but it checks `getIntent()` — the intent `Flag12Activity` was **itself launched with**. Since the activity is exported, that launching intent is just as attacker-controlled as everything else in this chain: whoever starts the activity gets to set `LOGIN` to whatever they want.

So the "careful" condition doesn't narrow who can trigger success — it just adds one more value the attacker needs to supply, which they can do trivially since they're the one launching the activity in the first place. Combined with the unchanged implicit-intent weakness from flag 11 (anyone can register `io.hextree.attacksurface.ATTACK_ME` and forge the token in the result), this flag is solved with the exact same catcher plus one extra flag on the initial `am start` call.

## Approach

1. Reuse the same `CatcherActivity` from [flag 11](../flag-11/exploit/CatcherActivity.kt) — no changes needed, since the response check (`token == 1094795585`) is identical.
2. Launch `Flag12Activity` directly, but this time also set the `LOGIN` boolean extra to `true` on the launching intent:

```bash
./gradlew installDebug
adb shell am force-stop io.hextree.attacksurface
adb shell am start -n io.hextree.attacksurface/.activities.Flag12Activity --ez LOGIN true
```

3. `Flag12Activity` fires the implicit `ATTACK_ME` intent exactly like flag 11; Android resolves it to `CatcherActivity`, which returns the forged token; `onActivityResult()` now also sees `LOGIN == true` on the original launch intent (because we set it ourselves), so both checks pass and the flag is released.

See [`exploit/CatcherActivity.kt`](./exploit/CatcherActivity.kt) — identical to flag 11's, included here for completeness.

## Why it works

Adding a check is only meaningful if the value being checked is something the attacker *doesn't* control. Here, both halves of the check are attacker-supplied: the `LOGIN` extra comes from the same exported-activity launch the attacker initiates, and the `token` comes from the same spoofable implicit-intent response as flag 11. Stacking two attacker-controlled checks together doesn't produce one trustworthy check — it's still zero actual verification of identity or of a real prior flow having happened.

## Fix

- Everything from [flag 10](../flag-10/README.md) and [flag 11](../flag-11/README.md) applies here too (explicit intents for internal communication, don't trust implicit-intent results as proof of caller identity).
- Additionally: a precondition that's meant to represent "the user already completed some other step" (like logging in) must be backed by real state — a session token issued by the app itself, a server-verified flag, something the current caller cannot simply set on the intent they're using to reach this screen. Checking `getIntent().getBooleanExtra(...)` on an exported component's own incoming intent checks nothing: that intent is attacker-authored input, not internal app state.
