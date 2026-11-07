# Flag 11 — Spoofing a Response to an Implicit Intent

**Vulnerability category:** Implicit intent resolution / hijacking
**Target component:** `io.hextree.attacksurface.activities.Flag11Activity`

---

## Target

Unlike [flag 10](../flag-10), here the target app itself initiates the attack surface: when `Flag11Activity` is opened with no explicit `action` set (i.e. launched normally), it fires its own implicit `Intent` with action `io.hextree.attacksurface.ATTACK_ME` via `startActivityForResult()`, and waits for a result.

Decompiled logic (JADX):

```java
protected void onCreate(Bundle bundle) {
    super.onCreate(bundle);
    this.f = new LogHelper(this);
    if (getIntent().getAction() == null) {
        Intent intent = new Intent("io.hextree.attacksurface.ATTACK_ME");
        intent.addFlags(8);
        startActivityForResult(intent, 42);
    }
}

protected void onActivityResult(int i, int i2, Intent intent) {
    if (intent != null && intent.getIntExtra("token", -1) == 1094795585) {
        this.f.addTag(1094795585);
        success(this);
    }
    super.onActivityResult(i, i2, intent);
}
```

The flag is released the moment `onActivityResult()` receives an `Intent` carrying an int extra `"token"` equal to `1094795585` (`0x41414141`, i.e. the ASCII bytes `"AAAA"`).

## Vulnerability

Same root cause as flag 10 — an implicit intent with no explicit destination is resolved against every installed app's matching `<intent-filter>`s — but here the attack surface is the **response**, not the initial delivery:

- The target app sends the implicit intent expecting *some* trusted component (presumably one of its own) to eventually resolve it and call `setResult()` with the expected token.
- Because resolution is implicit, any app that declares a matching `<intent-filter>` for `io.hextree.attacksurface.ATTACK_ME` can be the one Android hands the request to — and that app fully controls what it calls `setResult()` with.
- `Flag11Activity`'s check (`token == 1094795585`) only validates the *shape* of the response, not *who* produced it, so a hand-crafted result from an untrusted app passes exactly like a legitimate one would.

## Approach

Reused the same `CatcherActivity` registered for flag 10 (same `<intent-filter>` for `io.hextree.attacksurface.ATTACK_ME` / `DEFAULT`), but instead of just reading data from the incoming intent, it now responds with the exact token the target checks for:

```kotlin
class CatcherActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val result = Intent().apply {
            putExtra("token", 1094795585) // 0x41414141 == "AAAA"
        }
        setResult(RESULT_OK, result)
        finish()
    }
}
```

Steps:

1. Install the PoC app with `CatcherActivity` registered for the `ATTACK_ME` action (same manifest entry as flag 10).
2. Force-stop the target app to guarantee a clean `onCreate()`.
3. Launch `Flag11Activity` directly (no custom action, same as a normal app launch):
   ```bash
   ./gradlew installDebug
   adb shell am force-stop io.hextree.attacksurface
   adb shell am start -n io.hextree.attacksurface/.activities.Flag11Activity
   ```
4. `Flag11Activity` fires its implicit intent; Android resolves it to `CatcherActivity`, which immediately returns the expected token and finishes; control returns to `Flag11Activity.onActivityResult()`, the check passes, and the flag is released.

See [`exploit/CatcherActivity.kt`](./exploit/CatcherActivity.kt) for the full PoC code (manifest is unchanged from [flag 10's](../flag-10/exploit/AndroidManifest.xml)).

## Why it works

The target treats "I got a result with the right shape back from my implicit intent" as proof the request was handled by a trusted party. But implicit resolution never guaranteed *who* would answer — only that *something* matching the filter would. An attacker doesn't need to compromise the target app at all; they only need to be a plausible-enough handler for the action string, which is entirely learnable from the decompiled APK.

## Fix

- Don't drive sensitive logic off the result of an implicit intent sent for internal purposes. If the destination is meant to be the app's own component, address it explicitly (`setClassName()` / `setPackage()`) so Android can't hand the request — or the response — to anyone else.
- If an implicit intent must be used (e.g. to genuinely let the user choose a handler), never treat its result as proof of anything beyond "some app returned this data." Validate the actual identity of whoever answered (e.g. via `getCallingPackage()` on the receiving side, or redesign the flow to not need resolution-based trust at all).
- A fixed "magic" response value (`token == 1094795585`) is trivial to replay once an attacker can see the check in decompiled code — this is also a case of "security through an unguessable constant" that isn't actually unguessable once the APK is reverse engineered.
