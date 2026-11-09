# Flag 32 — SQL Injection via a ContentProvider's `selection` Argument

**Vulnerability category:** Content provider data exposure — SQL injection
**Target component:** `io.hextree.attacksurface.providers.Flag32Provider` (exported, no read/write permission)

---

## Target

Same unauthenticated-provider family as [flag 30](../flag-30) and [flag 31](../flag-31), but this one adds a second flaw on top: the `flags` route builds its SQL `WHERE` clause by directly concatenating the caller-supplied `selection` string:

```java
public Cursor query(Uri uri, String[] strArr, String str, String[] strArr2, String str2) {
    SQLiteDatabase readableDatabase = this.dbHelper.getReadableDatabase();
    int iMatch = uriMatcher.match(uri);
    if (iMatch != 1) {
        // ... FLAG_ID route, same pattern as flag 30/31
    }
    String str3 = "visible=1" + (str != null ? " AND (" + str + ")" : "");
    Log.i("Flag32", "FLAGS: " + str3);
    Cursor cursorQuery = readableDatabase.query(
        FlagDatabaseHelper.TABLE_FLAG, strArr, str3, strArr2, null, null, str2);
    if (containsFlag32(cursorQuery)) {
        LogHelper logHelper = new LogHelper(getContext());
        logHelper.addTag(uri.getPath());
        logHelper.addTag("flag32");
        success(logHelper);
        cursorQuery.requery();
    }
    return cursorQuery;
}

public boolean containsFlag32(Cursor cursor) {
    if (cursor == null) return false;
    int columnIndex = cursor.getColumnIndex(FlagDatabaseHelper.COLUMN_NAME);
    while (cursor.moveToNext()) {
        if ("flag32".equals(cursor.getString(columnIndex))) {
            return true;
        }
    }
    return false;
}
```

The provider intends every query against `flags` to be scoped to `visible=1`, with the caller's own `selection` (`str`) optionally narrowing it further via `AND (...)`. If the result set ends up containing a row named `"flag32"`, the provider writes the real flag value and returns it.

## Vulnerability

`str` — the `selection` argument a caller passes to `ContentResolver.query()` / `content query --where` — is wrapped in parentheses and `AND`-ed onto `visible=1`, but it is **never validated or parameterized**: it's raw SQL, inserted straight into the query string. The intent is presumably "the caller can only ever narrow the `visible=1` filter further," but string concatenation doesn't enforce that — the caller controls raw SQL syntax, including closing the parenthesis early and changing the boolean structure of the whole clause.

Supplying `1=1) OR (1=1` as the selection turns the final query into:

```sql
WHERE visible=1 AND (1=1) OR (1=1)
```

Due to normal SQL operator precedence (`AND` binds tighter than `OR`), this parses as `(visible=1 AND 1=1) OR (1=1)` — which is true for **every row**, regardless of its actual `visible` value. So a row that's normally hidden (`visible=0`) because the flag hasn't been "earned" yet gets returned anyway, satisfying `containsFlag32()` and triggering `success()`.

## Approach

Query the `flags` route with a crafted `selection` that always evaluates true, via `content query`'s `--where` option:

```bash
adb shell "content query --uri content://io.hextree.flag32/flags --where '1=1) OR (1=1'"
```

The provider builds `visible=1 AND (1=1) OR (1=1)`, which matches every row in the table — including the `flag32` row even if it isn't currently `visible=1` — and the provider's own `success()` logic fires as a side effect of the row showing up in the result.

## Why it works

This is a textbook SQL injection: untrusted input is concatenated into a query string instead of being passed as a bound parameter. `SQLiteDatabase.query()` already supports parameterized selections (the `selectionArgs` array, used correctly for the `name=?` comparisons elsewhere in this same class) — but the `visible=1 AND (...)` wrapping around the caller's raw `str` defeats that protection entirely, because the caller's string is itself unparameterized SQL fragments rather than a value substituted into a placeholder.

## Fix

- Never concatenate a caller-supplied `selection` string directly into SQL, even "wrapped" in another condition — wrapping only adds a prefix, it doesn't sanitize or restrict what the wrapped string can do.
- If a provider needs to accept caller-supplied filtering at all, validate the selection against an allow-list of expected column/operator patterns, or better, expose specific query parameters (not raw SQL) that the provider translates into parameterized queries itself.
- Combine this with the fixes from [flag 30](../flag-30/README.md#fix) / [flag 31](../flag-31/README.md#fix): the provider shouldn't be exported without a permission check in the first place, which would already have blocked this from being reachable externally at all.
