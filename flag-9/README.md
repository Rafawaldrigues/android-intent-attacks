# Flag 9 — Spoofing Caller Identity via Class Name String Match

**Vulnerability category:** Exported component — weak caller identity check
**Target component:** `io.hextree.attacksurface.activities.Flag9Activity` (exported)

---

## Target

An exported `Activity` that returns a result (`setResult()` + `RESULT_OK`, with the flag in a `"flag"` string extra) only to callers it considers legitimate. It identifies the caller using `getCallingActivity()`, which Android populates with the `ComponentName` of whoever launched it via `startActivityForResult()` — but it only checks that the calling class's **name contains the substring `"Hextree"`**, rather than verifying the caller's actual identity (package name, signing certificate, etc.).

## Vulnerability

`getCallingActivity()` is a legitimate, Android-provided way to find out which component started the current activity when `startActivityForResult()` was used (it returns `null` for `startActivity()`). That part is sound. The problem is what `Flag9Activity` does with that information: it performs a naive string check — presumably something like `callingActivity.className.contains("Hextree")` — as if matching part of a class name were proof that the caller belongs to a trusted app.

Class names are entirely attacker-controlled. Nothing stops any app, written by anyone, from naming its own `Activity` class `HextreeMain` (or anything else containing that substring) purely to satisfy this check. It carries no cryptographic or package-identity guarantee whatsoever — it's just a string the calling app chose for its own source file.

## Approach

1. Decompile `Flag9Activity` and confirm the identity check is based on the calling component's class name rather than its package name or signature.
2. Create a small launcher `Activity` whose class is deliberately named to satisfy the check (e.g. `HextreeMain`).
3. Start `Flag9Activity` with `startActivityForResult()` (not `startActivity()`) — this is required so `getCallingActivity()` on the target side actually returns a non-null value.
4. Read the flag back in `onActivityResult()`, from the `"flag"` extra of the returned `Intent`.

```kotlin
// The class name itself is the "exploit" here — it just needs to contain "Hextree".
class HextreeMain : Activity() {

    private val TARGET = "io.hextree.attacksurface"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val target = Intent().apply {
            setClassName(TARGET, "$TARGET.activities.Flag9Activity")
        }
        // Must use startActivityForResult() so getCallingActivity() on the
        // target side is populated.
        startActivityForResult(target, REQ)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        val flag = data?.getStringExtra("flag")
        // ... use the flag
    }
}
```

See [`exploit/HextreeMain.kt`](./exploit/HextreeMain.kt) for the full launcher used (the same technique also works against `Flag8Activity` by changing the target class name).

## Why it works

The check mistakes a piece of attacker-chosen metadata (a class name) for a trust signal. Any string comparison on data the caller fully controls — class name, package-declared label, app name shown in a manifest — provides no real identity guarantee. Real caller verification has to rely on something the OS enforces and the caller cannot forge: the calling package's name combined with its signing certificate (or a signature-level permission), not a substring of a Kotlin/Java class name.

## Fix

- Never use `getCallingActivity().className` (or any class/package *label*) as an authorization check. If caller identity matters, validate `getCallingActivity().packageName` against an allow-list **and** verify the caller's signing certificate (e.g. via `PackageManager` signature checks, or a `signature`-level custom permission declared by both apps).
- Prefer Android's built-in mechanisms for this: a signature-level permission on the component, or `Context.checkCallingPermission()` inside the activity, rather than hand-rolled string matching on data the caller supplies.
- Treat any identity check based on a value the other side gets to name (class name, intent extra, declared label) as providing no security guarantee by itself.
