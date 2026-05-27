# Countersign

Two-direction signing and webhook verification for payment/PSP integrations — in one small, dependency-free .NET library.

> **The insight behind it:** integrating a payment provider is two signing problems, not one.
> You **sign outbound** requests with your key, and you **verify inbound** webhooks with *theirs*.
> Those two directions usually use **different canonical forms** and **different secrets** — and conflating
> them is the bug that silently passes in the sandbox and fails in production. Countersign keeps the two
> directions explicitly separate so you can't mix them up.

## Why this exists

Every PSP integration re-implements the same crypto plumbing — HMAC over some canonical string, a header
to compare in constant time, a webhook secret that is *not* the API secret. It's easy to get subtly wrong:

- signing the wrong canonical form (raw body vs. method+path+timestamp+body),
- reusing the API secret to verify webhooks instead of the dedicated webhook secret,
- comparing signatures with `==` (timing leak) instead of a constant-time compare,
- forgetting replay protection on the inbound timestamp.

Countersign packages these as two clearly separated concerns: **Sign** (outbound) and **Verify** (inbound).

## Status

🚧 Early scaffold. Public API (`Sign` / `Verify`) lands next — see the roadmap.

## Roadmap

- [x] Project scaffold (multi-target `netstandard2.0` + `net8.0`, tests, CI-ready)
- [ ] Public API: split `Sign` (outbound) and `Verify` (inbound), separate webhook secret
- [ ] Core HMAC signing with configurable canonical form per direction
- [ ] Webhook verification with dedicated secret + timestamp/replay handling
- [ ] Tests: known-answer vectors; outbound ≠ inbound canonical-form cases
- [ ] Publish `0.1.0` to NuGet

## License

MIT — see [LICENSE](LICENSE).
