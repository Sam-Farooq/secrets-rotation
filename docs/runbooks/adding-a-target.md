# Runbook: adding a target

The database side has to exist before the tool will touch it. This tool
rotates; it does not create the first credential, and it will not create a
role.

## 1. Two roles, with the same grants

The two user pattern needs two roles that are interchangeable. Create them
with identical membership, or the rotation will work and then half the queries
will fail on whichever cycle lands on the role that is missing a grant.

    CREATE ROLE orders_app_a LOGIN PASSWORD '<40 random characters>';
    CREATE ROLE orders_app_b LOGIN PASSWORD '<40 random characters>';
    GRANT orders_app TO orders_app_a, orders_app_b;

Granting both into one group role is the only way this stays true over time.
Two roles with grants applied directly will drift the first time somebody
grants a new table to one of them.

## 2. The secret, with one of the two users in it

Secrets Manager, created by whatever owns your secrets, holding exactly:

    {"username": "orders_app_a", "password": "<the password you just set>"}

`username` and `password` are both required. A secret with `user` instead of
`username` fails on the first read with a message naming the missing key.

For a Vault target the document is:

    {"current": {"username": "...", "password": "..."}}

`rotated_at` is absent until the first rotation, and until then `plan` reports
the age as unknown and the target as blocked. That is deliberate: the age of a
credential this tool has never rotated is not something it can honestly guess.

## 3. targets.toml

    [[target]]
    name = "orders-db"
    store = "secretsmanager"
    secret_id = "prod/orders/app"
    users = ["orders_app_a", "orders_app_b"]
    schedule = "cron(15 3 ? * SUN *)"

Anything omitted comes from `[defaults]`. Override `quiesce_seconds` if this
target's consumers hold a credential for longer than the default window: a
batch worker that keeps a connection for the length of a job needs the job
timeout, not the cache TTL.

`config.load` refuses a `quiesce_seconds` that is not longer than
`consumer_cache_seconds`, which is the one mistake in this file that would
cause an outage rather than a failed job.

## 4. Render, and commit what it writes

    python3 scripts/render.py

That writes `terraform/generated/rotation_policy.json` and
`terraform/generated/targets.json`. Commit both. CI runs
`scripts/render.py --check` and fails if they are stale, because a target with
a schedule and no IAM permission fails at 03:15 on a Sunday.

## 5. Apply

    cd terraform
    terraform plan
    terraform apply

The plan adds one `aws_scheduler_schedule` and changes one inline policy. If
it proposes anything else, stop and read why.

## 6. Prove it before the schedule does

    rotator plan --target orders-db

Expect `ok`, an age, and the other user as the next one. Then, once, by hand:

    rotator rotate --target orders-db --confirm

Watch it reach `revoked`. A target whose first rotation is unattended at 03:15
is a target whose `pg_hba.conf` gap you find out about from an alert.
