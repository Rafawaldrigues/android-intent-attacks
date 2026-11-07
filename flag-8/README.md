# Flag 8 — Spoofing Caller Identity via Class Name String Match

**Vulnerability category:** Exported component — weak caller identity check
**Target component:** `io.hextree.attacksurface.activities.Flag8Activity` (exported)

---

## Target

Same vulnerability as [flag 9](../flag-9): an exported `Activity` that returns a result only to callers it considers legitimate, identified via `getCallingActivity()` — but validated with a naive check that the calling class's **name contains the substring `"Hextree"`**, instead of actually verifying the caller's package and signing certificate.

See the [flag 9 write-up](../flag-9/README.md) for the full breakdown of why this check is meaningless (class names are attacker-controlled data, not a trust signal) and how it's fixed. This entry only covers the one thing that differs for flag 8: the target component.

## Approach

Reused the exact same launcher app and technique as flag 9 — a class named `HextreeMain` (to satisfy the `"Hextree"` substring check) calling `startActivityForResult()` — just pointed at `Flag8Activity` instead of `Flag9Activity`:

```kotlin
val target = Intent().apply {
    setClassName(TARGET, "$TARGET.activities.Flag8Activity")
}
startActivityForResult(target, REQ)
```

Build, install, and run:

```bash
./gradlew installDebug

# force a clean onCreate() for the launcher
adb shell am force-stop com.poc.intents

# fire it
adb shell am start -n com.poc.intents/.HextreeMain
```

`onActivityResult()` on the launcher side then receives the flag the same way as in flag 9 — `data?.getStringExtra("flag")`.

See [`exploit/HextreeMain.kt`](./exploit/HextreeMain.kt) for the full launcher code (identical to flag 9's, with the target class name swapped).

## Why it works / Fix

Identical root cause and fix as [flag 9](../flag-9/README.md): the check trusts attacker-chosen class name data instead of verifying the caller's package name and signing certificate. Don't validate identity with a string match on data the caller controls — use `PackageManager` signature checks or a signature-level permission instead.
