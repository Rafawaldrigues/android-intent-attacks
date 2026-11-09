# Flag 31 — Unauthenticated ContentProvider Read via `UriMatcher` Path

**Vulnerability category:** Content provider data exposure
**Target component:** `io.hextree.attacksurface.providers.Flag31Provider` (exported, no read/write permission)

---

## Target

Same vulnerability class as [flag 30](../flag-30), on a provider that routes queries through a `UriMatcher` instead of a flat path string:

```java
static {
    uriMatcher.addURI(AUTHORITY, "flags", 1);     // FLAGS
    uriMatcher.addURI(AUTHORITY, "flag/#", 2);    // FLAG_ID — '#' matches a numeric segment
}

public Cursor query(Uri uri, String[] strArr, String str, String[] strArr2, String str2) {
    SQLiteDatabase readableDatabase = this.dbHelper.getReadableDatabase();
    int iMatch = uriMatcher.match(uri);
    if (iMatch == 1) {
        throw new IllegalArgumentException("FLAGS not implemented yet: " + uri);
    }
    if (iMatch == 2) {
        long id = ContentUris.parseId(uri);
        if (id == 31) {
            LogHelper logHelper = new LogHelper(getContext());
            logHelper.addTag(uri.getPath());
            success(logHelper);
        }
        return readableDatabase.query(FlagDatabaseHelper.TABLE_FLAG, strArr,
            "name=? AND visible=1", new String[]{"flag" + id}, null, null, str2);
    }
    throw new IllegalArgumentException("Unknown URI: " + uri);
}
```

Querying `content://io.hextree.flag31/flag/31` matches the `flag/#` pattern with `id = 31`, which both writes the flag into the database (`success()`, same as flag 30) and returns it in the resulting row.

## Vulnerability

Identical root cause to flag 30: `Flag31Provider` is exported with no `readPermission`, `writePermission`, or `<path-permission>`, so `query()` is reachable and fully functional for any caller — no identity or permission check happens anywhere in the method. The only difference from flag 30 is cosmetic: the provider uses a `UriMatcher` to route numeric `flag/{id}` paths instead of a single hardcoded `/success` path, but that routing logic adds structure, not security — it still executes the same unauthenticated write-then-read for whichever `id` is requested.

## Approach

Query the provider directly, same as flag 30, targeting the `flag/31` path this provider's `UriMatcher` expects:

```bash
adb shell content query --uri content://io.hextree.flag31/flag/31
```

The returned row (`name = "flag31"`) includes the flag written by `success()` during that same query.

## Why it works

Same as [flag 30](../flag-30/README.md#why-it-works): an exported `ContentProvider` without any permission enforcement is queryable by anything that can build a matching URI, `adb shell content query` included. Structuring the provider's URI space with a `UriMatcher` is good practice for routing, but it does nothing on its own to restrict *who* can hit any given route.

## Fix

Same as [flag 30](../flag-30/README.md#fix): set `android:exported="false"` if the provider has no legitimate external consumers, or enforce `android:readPermission` / `android:writePermission` (optionally scoped per-path with `<path-permission>`) so only trusted, signature-verified callers can query it. And again, avoid mutating state (regenerating/writing the flag) as a side effect of a `query()` call — reads shouldn't have write side effects, authenticated or not.
