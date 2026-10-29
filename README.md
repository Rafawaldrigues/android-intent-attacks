# Android Intent Attacks — CTF Write-ups

Personal write-ups documenting the challenges I solved in the **Intents** track on [hextree.io](https://hextree.io). Each entry explains the vulnerability, how it was found, and the approach used to capture the flag.

These notes are my own summary of what I did to solve each exercise — not a copy of the course material.

## Disclaimer

This repository is for **educational purposes only**, documenting my own progress through a security training platform. The techniques described here apply to deliberately vulnerable practice apps.

I am **not responsible** for any misuse of this information. Do not use these techniques against applications, systems, or companies without explicit authorization. Unauthorized access to computer systems is illegal in most jurisdictions.

## Structure

Write-ups are organized by Android Intent vulnerability category:

- [`implicit-intents/`](./implicit-intents) — Issues arising from implicit intent resolution and hijacking.
- [`exported-components/`](./exported-components) — Exported Activities, Services, and Broadcast Receivers reachable by other apps.
- [`pending-intents/`](./pending-intents) — PendingIntent misuse and mutability issues.
- [`intent-redirection/`](./intent-redirection) — Intent redirection / confused deputy issues.
- [`deep-links/`](./deep-links) — Deep link and App Link handling flaws.
- [`broadcast-receivers/`](./broadcast-receivers) — Vulnerable broadcast receivers.
- [`content-providers/`](./content-providers) — Data leaks via content providers reachable through intents.

Each flag write-up folder contains:

```
flag-N/
├── README.md     # Explanation of the vulnerability and solution steps
└── exploit/       # Any supporting code (PoC app, script, adb commands)
```

## Format

Each write-up follows the same outline:

1. **Challenge summary** — what the app does and the attack surface exposed.
2. **Vulnerability** — the underlying Android Intent weakness being exploited.
3. **Approach** — how the flag was found and exploited.
4. **Fix** — how the issue would be mitigated in a real app.

## License

Write-ups are shared as-is for learning purposes. No warranty of any kind.
