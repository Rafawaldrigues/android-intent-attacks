# Flag 30 — Reading the Flag Straight Out of an Unprotected ContentProvider

**Vulnerability category:** Content provider data exposure
**Target component:** `io.hextree.attacksurface.providers.Flag30Provider` (exported, no read/write permission)

---

## Target

`Flag30Provider` is a `ContentProvider` that answers queries against a specific path. When queried at `/success`, it both **writes** the flag into its own database and **returns** it in the resulting `Cursor` — all from a single, unauthenticated `query()` call:

```java
public Cursor query(Uri uri, String[] strArr, String str, String[] strArr2, String str2) {
    Log.i("Flag30", "Flag30Provider.query('" + uri.getPath() + "')");
    if (!uri.getPath().equals("/success")) {
        return null;
    }
    LogHelper logHelper = new LogHelper(getContext());
    logHelper.addTag(uri.getPath());
    Cursor cursorQuery = this.dbHelper.getReadableDatabase().query(
        FlagDatabaseHelper.TABLE_FLAG, strArr, "name=? AND visible=1",
        new String[]{"flag30"}, null, null, str2);
    cursorQuery.setNotificationUri(getContext().getContentResolver(), uri);
    success(logHelper);
    return cursorQuery;
}

public String success(LogHelper logHelper) {
    ContentValues contentValues = new ContentValues();
    String strAppendLog = logHelper.appendLog(Flag30Activity.FLAG);
    contentValues.put(FlagDatabaseHelper.COLUMN_VALUE, strAppendLog);
    this.dbHelper.getReadableDatabase().update(
        FlagDatabaseHelper.TABLE_FLAG, contentValues, "name=?", new String[]{"flag30"});
    // ... also launches Flag30Activity with a "secret" extra, unrelated to reading the flag
    return strAppendLog;
}
```

## Vulnerability

`ContentProvider`s are reachable by any app on the device unless explicitly restricted — via `android:exported="false"`, a `android:readPermission` / `android:writePermission`, or (on recent Android versions) a `<path-permission>` scoped to specific URI paths. `Flag30Provider` declares none of these, so:

- Any installed app (or `adb shell content query`, which talks to providers the same way) can issue a `query()` against `content://io.hextree.flag30/success`.
- That single query both writes the flag into the row the provider manages (via `success()`) and returns the resulting row — the `name="flag30"` record — in the `Cursor` handed back to the caller.
- There's no check anywhere in `query()` of who's calling — no `getCallingPackage()`, no permission enforcement, nothing. The method does exactly the same thing regardless of caller.

This is a straightforward **content provider exposure**: a component meant to serve as the app's own internal data layer is reachable, unauthenticated, from any other app on the device.

## Approach

No PoC app or decompiling beyond identifying the provider's authority and path was needed — the provider can be queried directly from the command line, the same way Android's `ContentResolver` would:

```bash
adb shell content query --uri content://io.hextree.flag30/success
```

The returned row includes the flag (the `value` column, written by `success()` right before the cursor is returned).

## Why it works

Exporting a `ContentProvider` without any `readPermission` means its `query()` method is callable by literally anything that can form the right `content://` URI — there's no implicit trust boundary the way there sometimes (wrongly) is assumed for other component types. `adb shell content query` is functionally equivalent to a malicious app calling `ContentResolver.query()` with the same URI; both go through the exact same unauthenticated code path.

## Fix

- Set `android:exported="false"` on the provider if no other app genuinely needs to query it.
- If external access is required, declare `android:readPermission` (and `android:writePermission` separately, if writes are ever exposed) with a signature-level custom permission, so only apps signed by the same key — or explicitly trusted apps declaring that permission — can query it.
- For finer-grained control, use `<path-permission>` entries to protect sensitive paths (like `/success`, which here both mutates state and discloses a secret) differently from less sensitive ones.
- Avoid side effects (writing/regenerating a secret) as a consequence of a plain read (`query()`) — a `query` should be read-only; state changes belong behind an explicit, authenticated write path.
