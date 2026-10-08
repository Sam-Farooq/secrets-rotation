# Why a rotation is nine states and not one function

A credential cannot be revoked until every consumer holds the new one. That
single sentence is the reason none of this is a single function.

The naive version sets a new password and writes it to the store. It works
every time until the write fails, or a consumer is holding the old one in a
module global, or the new password turns out not to work because the role was
locked three months ago and nobody noticed. Then the service is down and the
only credential that worked has been overwritten.

## The sequence

```
         ┌─────────┐  create   ┌─────────┐  set_password  ┌─────┐
         │ pending │──────────►│ created │───────────────►│ set │
         └────┬────┘           └────┬────┘                └──┬──┘
              │ abort               │ abort      verify_failed│   │ verify_ok
              │                     │             or abort    │   │
              ▼                     ▼                         ▼   ▼
         ┌───────────────────────────────────────────┐   ┌──────────┐
         │             rolled_back                   │◄──│ verified │
         └───────────────────────────────────────────┘   └────┬─────┘
                            nothing was revoked               │ promote
                                                              ▼
                                                        ┌──────────┐
          ════════════ point of no return ══════════════│ promoted │
                                                        └────┬─────┘
                                                  give_up    │ quiesce
                                                      │      ▼
                                                      │ ┌──────────┐
                                                      │ │ quiesced │
                                                      │ └──┬────┬──┘
                                                      │    │    │ revoke
                                                      ▼    ▼    ▼
                                              ┌─────────────┐ ┌─────────┐
                                              │  abandoned  │ │ revoked │
                                              └─────────────┘ └─────────┘
                                               needs a human    done
```

Nine states, thirteen legal transitions, eight routes from `pending` to an
end. Exactly one of those eight revokes anything, and it is the only one with
`verify_ok` and `promote` in it. `tests/test_machine_safety.py` enumerates all
eight and asserts that.

## What each phase is for

**create.** A new password is written where nobody reads it: `AWSPENDING` in
Secrets Manager, a `pending` field in Vault. Writing it before installing it
means a crash between the two leaves a password in the store that works
nowhere, which is harmless. The other order leaves a working password nobody
has, which is not.

**set_password.** The password is installed on the user nobody is connecting
as. This is the two user pattern and it is the whole reason the dangerous
window is short: the live credential is not touched at any point in the
sequence until the very end.

**verify.** The new credential is used to authenticate, as that user. Three
attempts with five seconds between them, because `ALTER ROLE` is immediate on
the primary and a verify routed to a replica can arrive before the change
does.

**promote.** The publish. One `UpdateSecretVersionStage` call, or one KV v2
write with `cas`. After this, consumers resolve the new credential.

**quiesce.** Wait out the longest cache any consumer keeps the credential in.
`consumer_cache_seconds` in `targets.toml` is the declared budget and every
target's `quiesce_seconds` has to exceed it, which `config.load` enforces.

**revoke.** The old user's password is scrambled. Not dropped, not stripped of
grants: it is the user the next rotation but one will use.

## Why there is no rollback after the promote

Before the promote, undoing is free: discard the staged value and stop. The
live credential was never touched.

After the promote, undoing means putting the old credential back in front of
consumers that may already have fetched the new one. A consumer that refreshed
in that window is now holding a credential the store no longer publishes and
that nothing will reinstate. So the machine does not offer it. `abort` is not
a legal event from `promoted` or `quiesced`, and the only exit is `give_up`,
which stops and says a person is needed.

That asymmetry is the design. It is also why the quiesce window being longer
than the cache TTL is a config error rather than a warning: it is the one
number that decides whether the forward-only half of the sequence is safe.
