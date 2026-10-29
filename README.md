# Android Intent Attacks — CTF Write-ups

Personal write-ups documenting the challenges I solved in the **Intents** track on [hextree.io](https://hextree.io). Each entry explains the vulnerability, how it was found, and the approach used to capture the flag.

These notes are my own summary of what I did to solve each exercise — not a copy of the course material.

## Disclaimer

This repository is for **educational purposes only**, documenting my own progress through a security training platform. The techniques described here apply to deliberately vulnerable practice apps.

I am **not responsible** for any misuse of this information. Do not use these techniques against applications, systems, or companies without explicit authorization. Unauthorized access to computer systems is illegal in most jurisdictions.

## Structure

Each flag has its own top-level folder:

```
flag-N/
├── README.md     # Explanation of the vulnerability and solution steps
└── exploit/       # Any supporting code (PoC app, script, adb commands), when applicable
```

## Flags

| Flag | Vulnerability category | Write-up |
|------|------------------------|----------|
| 2 | Exported component | [`flag-2/`](./flag-2) |
| 3 | Deep link / App Link trust bypass | [`flag-3/`](./flag-3) |
| 4 | Exported component — multi-step flow / state machine | [`flag-4/`](./flag-4) |

Categories covered across this repo include: exported components (Activities, Services, Broadcast Receivers), implicit intent resolution, PendingIntent misuse, intent redirection, deep links / App Links, and content providers reachable through intents. Each write-up's **Vulnerability** section states which category it falls under.

## Format

Each write-up follows the same outline:

1. **Challenge summary** — what the app does and the attack surface exposed.
2. **Vulnerability** — the underlying Android Intent weakness being exploited.
3. **Approach** — how the flag was found and exploited.
4. **Fix** — how the issue would be mitigated in a real app.

## License

Write-ups are shared as-is for learning purposes. No warranty of any kind.
