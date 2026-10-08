# Runbook: a rotation stopped before the promote

**The audit line ends `"to": "rolled_back"`.** Any event: `abort`,
`verify_failed`.

## What is true right now

- Consumers are using the credential they were using before. Nothing was
  published.
- Nothing was revoked. The live password still works.
- The inactive user may be holding a password nobody has a copy of. That is
  expected and is not a fault: nothing connects as it, and the next rotation
  sets it again.
- There may be a staged credential left in the store if the rollback's own
  cleanup also failed.

**Nobody is paged for this.** It is a failed job, not an incident. The service
is serving.

## What to do

1. Read the last audit line. The `detail` field says which step failed and why.

       tail -n 3 /var/log/rotator/<target>.audit.jsonl | python3 -m json.tool

2. Confirm the target is clean:

       rotator status --target <target>

   `staged none` means the rollback finished. `staged <user>` means it did not.

3. If something is staged, drop it:

       rotator discard <target>

4. Then work out why. Three things to check, cheapest first:

   **`verify_failed` with three attempts and no error.** The role cannot log
   in. Check `rolvalid` and `rolcanlogin` on it, and whether `pg_hba.conf`
   has a rule matching that role from the task's subnet. A role created by
   hand months ago and never used is the usual answer.

   **`abort` with `ALTER ROLE ... failed: PermissionDenied`.** The admin role
   lost `CREATEROLE`, or the target role was granted to somebody else and the
   admin is no longer a member. `ALTER ROLE ... PASSWORD` needs membership
   with `ADMIN OPTION`, or superuser.

   **`abort` with a Secrets Manager error.** Compare the secret in the error
   against `terraform output rotated_secret_arns`. A secret renamed outside
   this repo is outside the policy, and the IAM denial does not say which
   secret it was.

5. Re-run when the cause is fixed. A rotation that has rolled back leaves
   nothing to resume from, so this is a fresh run:

       rotator plan --target <target>
       rotator rotate --target <target> --confirm

## What not to do

Do not reach into Secrets Manager and move staging labels by hand. The store
is the only record of where a run got to, and a label moved by hand makes the
next `plan` report something that is not true.
