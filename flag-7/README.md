# Flag 7 — Faking a "Reopen" via `onNewIntent` + `FLAG_ACTIVITY_SINGLE_TOP`

**Vulnerability category:** Exported component — Activity lifecycle trust
**Target component:** `io.hextree.attacksurface.activities.Flag7Activity` (exported)

---

## Target

An exported `Activity` whose logic distinguishes between two different lifecycle entry points:

- `onCreate()` — fired when the activity is created fresh.
- `onNewIntent()` — fired when the activity is already the top instance on the stack and receives a new intent, instead of being recreated (this requires either `FLAG_ACTIVITY_SINGLE_TOP` on the caller's intent, or the activity declaring `launchMode="singleTop"`/similar in the manifest).

The activity appears to track an internal state that's set one way on `onCreate()` (e.g. `OPEN`) and a different way on `onNewIntent()` (e.g. `REOPEN`), and the flag logic depends on this second state actually being reached through the "reopen" code path.

## Vulnerability

The activity trusts *how* it was entered — fresh creation vs. being reopened on top of the stack — as if that distinction were meaningful proof of some legitimate interaction flow. But since the activity is exported, an outside app (or `adb`) fully controls both:

1. The first intent that creates it (action `OPEN`), and
2. The second intent, sent with `FLAG_ACTIVITY_SINGLE_TOP`, that reuses the existing top instance and routes through `onNewIntent()` (action `REOPEN`).

Nothing about this sequence requires real user interaction or a legitimate internal flow — it's just two `am start` calls (or two `startActivity()` calls from a PoC app) with the right action and the right intent flag.

## Approach

1. Make sure no stale instance of the target app is running, so the activity starts from a clean state:
   ```bash
   adb shell am force-stop io.hextree.attacksurface
   ```
2. Start the activity fresh with the action that drives it through `onCreate()`:
   ```bash
   adb shell am start -n io.hextree.attacksurface/.activities.Flag7Activity -a OPEN
   ```
3. Immediately send a second intent at the same component, with `FLAG_ACTIVITY_SINGLE_TOP` set, so it's delivered to the already-running top instance via `onNewIntent()` instead of recreating the activity:
   ```bash
   adb shell am start -n io.hextree.attacksurface/.activities.Flag7Activity -a REOPEN --activity-single-top
   ```

The confirmation that the second call actually reused the existing instance (and therefore went through `onNewIntent()`, not `onCreate()`) shows up directly in the `am` output:

```
Starting: Intent { act=OPEN cmp=io.hextree.attacksurface/.activities.Flag7Activity }
Starting: Intent { act=REOPEN flg=0x20000000 cmp=io.hextree.attacksurface/.activities.Flag7Activity }
Warning: Activity not started, intent has been delivered to currently running top-most instance.
```

That warning is exactly the signal that `flg=0x20000000` (`FLAG_ACTIVITY_SINGLE_TOP`) worked as intended and the intent was routed to `onNewIntent()` on the existing instance — satisfying the activity's "was properly reopened" check and releasing the flag.

## Why it works

The activity's state transition (`OPEN` → `REOPEN`) is only meant to represent how the system delivered the intent, but it's being used as if it were evidence of a trustworthy flow. Since the activity is exported, an attacker fully controls:

- Which action string is sent at each step.
- Whether `FLAG_ACTIVITY_SINGLE_TOP` is set, which decides whether `onCreate()` or `onNewIntent()` handles the next intent.

There's no actual security boundary between "the user navigated back into this screen" and "an external caller sent two crafted intents in a row." Lifecycle callbacks are an implementation detail of how Android delivers intents, not an authorization mechanism.

## Fix

1. **Don't export** the component if it doesn't need to receive intents from outside the app: `android:exported="false"`.
2. **Don't treat lifecycle methods as proof of a legitimate flow.** Which callback fires (`onCreate` vs `onNewIntent`) depends entirely on intent flags the caller controls — it says nothing about who the caller is or whether a real multi-step interaction happened.
3. If a reopen/resume flow needs to be meaningful for security purposes, back it with actual session/state validation (e.g. a server-side check, a timestamp/nonce tied to the original flow) rather than which Android callback happened to run.
