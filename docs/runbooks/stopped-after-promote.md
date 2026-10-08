# Runbook: a rotation stopped after the promote

**The audit line ends `"to": "abandoned"`, `"ok": false`.** The event is
`give_up`. The exit code from `rotator rotate` was 3.

This is the only state in the machine that needs a person.

## What is true right now

- **The new credential is published and working.** It was verified before the
  promote, so consumers are authenticating with it.
- **The old credential is also still working.** The revoke did not happen, or
  it failed.
- Nothing is staged. The promote consumed it.

So the service is up. What you have is a least privilege finding: a database
role whose password is sitting in the `AWSPREVIOUS` version of a secret and in
whatever logs the last six months of deploys wrote. It is not an outage and it
does not get fixed by restarting anything.

## Why nothing retried it

The schedule is declared with `maximum_retry_attempts = 0`. A schedule cannot
tell a task that never started from one that died between promote and revoke,
and a retry of the second starts a fresh rotation against a target whose live
credential has just changed. That run would refuse and report blocked, which
is correct and is also a second alert for one incident.

So this state is reached and left alone, on purpose, until somebody reads this
file.

## What to do

1. Confirm which user is live and which one needs revoking:

       rotator status --target <target>

   `current <user>` is the new one. The other declared user is the one still
   holding a password it should not.

2. Check the audit for how far it got:

       tail -n 5 /var/log/rotator/<target>.audit.jsonl | python3 -m json.tool

   `"to": "promoted"` means it died during the quiesce window, so the revoke
   was never attempted. `"to": "quiesced"` means the revoke itself failed and
   `detail` says how.

3. Revoke the old password by hand. Connect as the admin role and set it to
   something nobody records:

       ALTER ROLE <old_user> WITH PASSWORD '<40 random characters>';

   Do not `DROP ROLE` and do not `REVOKE` its grants. That role is what the
   next rotation but one will use, and rebuilding its grants from memory is
   how a reporting job loses access three months from now.

4. Check whether the quiesce window was actually waited out before you do it.
   If the task died at `promoted` within seconds of the promote, consumers
   caching the old credential for up to `consumer_cache_seconds` have not all
   refreshed. Wait the rest of the window out first. The sum of `at`
   timestamps in the audit tells you how long it ran.

5. Confirm nothing is still using the old credential before and after:

       SELECT usename, count(*), max(backend_start)
       FROM pg_stat_activity WHERE usename = '<old_user>' GROUP BY usename;

   A connection older than the promote is a consumer that has not refreshed.
   Killing it is a decision, not a step in this runbook.

6. The next scheduled run rotates back to the old user and will set its
   password again. Nothing needs resetting for that to work.

## The one that is not covered here

If the revoke failed because the database was unreachable, and it is still
unreachable, there is nothing to do in this file. The credential stays live
until there is a database to revoke it on. Note it and come back.

## Check `log_statement` while you are here

`ALTER ROLE ... WITH PASSWORD` sends the password in the statement text. A
server with `log_statement = 'ddl'` or `'all'` has written every password this
tool has ever set into its own log. Confirm it is `'none'` or `'mod'`:

    SHOW log_statement;

If it is not, the rotation history is in the log and rotating again does not
remove it.
