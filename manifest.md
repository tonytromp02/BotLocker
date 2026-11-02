# Botlocker Manifest

## Why we exist

Bots scrape our content and abuse our infrastructure. They take what we publish without consent, without credit, and without compensation. They burn bandwidth, inflate our costs, and degrade the experience for the people we actually build for.

We are tired of it. Botlocker exists to make abusive scraping expensive and pointless.

## Mission

Make abusive scraping costly and pointless, and protect the content creators have made.

## Goals

- **Protect real users.** Humans never see a trap and never lose access.
- **Protect good bots.** Search engines and verified, allowlisted crawlers keep working.
- **Impose cost on abusers.** Bots that ignore the rules spend their own time and resources going nowhere.
- **Stay simple to deploy.** It should run at the Cloudflare edge or on a local machine with minimal setup.
- **Stay transparent.** How we detect and what we do is documented and open to inspection.

## Values

- **Consent over extraction.** Our content is ours to offer, not to take.
- **Defense, not offense.** We only waste the time of bots that ignore our rules. We never attack third parties, never deliver malware, and never exploit anything.
- **Zero harm to humans.** A misclassified visitor must have an easy way out and must never be served anything harmful.
- **Simplicity.** Small, understandable components beat clever ones.
- **Transparency.** We honor `robots.txt`, document our behavior, and say plainly what we do.

## Principles

- Trap only on clear signals, never on a hunch.
- Serve only harmless, generated filler content.
- Allowlist verified good crawlers before anything else.
- Keep a kill switch and hard resource caps so the trap can never run away.
