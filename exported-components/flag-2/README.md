# Flag 2 — Exported Activity Reachable via Explicit Intent

## Challenge summary

The target app exposes an `Activity` (`Flag2Activity`) that is declared as `exported="true"` in its manifest. The activity is meant to hand out a flag when it receives a specific `Intent` action, but it performs no check on which app is calling it and no permission is required to launch it.

Because any component marked `exported` can be started directly by another installed app (as long as you know its package and class name), this activity is part of the app's public attack surface even though it was probably intended to be triggered only from inside the app itself.

## Vulnerability

- `Flag2Activity` is exported in the manifest with no `android:permission` attribute.
- The activity's logic is gated only by checking the incoming `Intent.action` — there is no verification of the caller's identity (e.g. via `getCallingPackage()`, a signature-level permission, or `android:exported="false"`).
- Any third-party app can therefore construct an `Intent` with the expected action and launch the activity directly to trigger the flag-granting code path.

This is a classic **exported component** issue: sensitive functionality is reachable from outside the app's own process because the component boundary (export + permission) wasn't locked down.

## Approach

1. Decompile the target APK to find the target package and the exact component name of `Flag2Activity`, and read its code to see which `Intent.action` string it expects.
2. Write a minimal "launcher" app containing a single `Activity` that, on creation, builds an **explicit** `Intent`:
   - `setClassName(targetPackage, targetPackage + ".activities.Flag2Activity")`
   - `action = "<the action string Flag2Activity checks for>"`
3. Call `startActivity()` with that intent from the launcher app.
4. Install both APKs on the same device/emulator, launch the launcher app, and observe the target activity run its flag logic (read via `adb logcat`, or whatever UI/output the challenge exposes).

Since the intent is explicit (`setClassName`), Android does not need the target activity to declare an `<intent-filter>` — exporting it is enough for any app to reach it directly, bypassing whatever implicit-intent restrictions might otherwise apply.

See [`exploit/MainActivity.kt`](./exploit/MainActivity.kt) for the launcher code used.

## Fix

- Set `android:exported="false"` on `Flag2Activity` if it is never meant to be launched from outside the app.
- If it *does* need to be reachable externally, enforce a signature-level `android:permission` so only apps signed with the same key (or explicitly trusted) can start it.
- Never gate sensitive logic purely on the contents of an `Intent` (action, extras) — always also validate the caller when the component is exported.
