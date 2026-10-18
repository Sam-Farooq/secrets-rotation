# secrets-rotation

`eks-infra` generates an RDS password, writes it to Secrets Manager, and
nothing ever rotates it. This is the job that rotates it, the Terraform that
says when, and the paperwork for the night it stops halfway.

A rotation is not one action, because a credential cannot be revoked until
every consumer holds the new one. So it is nine states and thirteen legal
transitions, with a point of no return in the middle.

```
rotator/              the job: a state machine, two stores, one database adapter
terraform/            when it runs, and exactly which secrets it may touch
terraform/generated/  rendered from targets.toml, committed, drift checked in CI
docs/two-phase.md     the state diagram and why there is no rollback at the end
docs/runbooks/        what is true, and what to do, per state it can stop in
targets.toml          the only list of targets in the repo
```

## If it stops, it stops somewhere specific

This is the table the runbooks are built on. Every row is a state the machine
can be in when the process dies.

| Stopped at | The live credential | Published | Old one revoked | Who cares |
|---|---|---|---|---|
| `pending` | untouched | no | no | nobody |
| `created` | untouched | no | no | nobody. A staged value is left; `rotator discard` drops it |
| `set` | untouched | no | no | nobody. The inactive user holds a password no one has, which is what the next run overwrites |
| `verified` | untouched | no | no | nobody |
| `promoted` | **the new one** | yes | no | a person. Both credentials work |
| `quiesced` | **the new one** | yes | no | a person. Same, and the quiesce window has elapsed |
| `revoked` | the new one | yes | yes | nobody. Done |

The first four rows are one runbook,
[`stopped-before-promote.md`](docs/runbooks/stopped-before-promote.md): a
failed job, not an incident, and the service is serving throughout.

The two bold rows are the other one,
[`stopped-after-promote.md`](docs/runbooks/stopped-after-promote.md). Nothing
is down there either. What is wrong is that two passwords open the same
database and only one of them is in the store, which is a least privilege
finding that no restart fixes and nothing automatic will clear.

Eight routes run from `pending` to an end. One of them revokes anything, and
it is the only one containing both `verify_ok` and `promote`.
`tests/test_machine_safety.py` enumerates all eight and asserts that, which is
why the table is data in `rotator/machine.py` rather than a chain of ifs.

## The two user pattern

Two database roles, interchangeable, with their grants held through one group
role. Exactly one of them is in the secret at any time, and a rotation always
acts on the other.

    secret says orders_app_a       ->  rotate orders_app_b
    verify orders_app_b works      ->  publish it
    wait out the cache window      ->  scramble orders_app_a

So the credential in front of traffic is not touched at any point until the
last step, and that step runs only after the replacement has authenticated as
itself. Next cycle it runs the other way round.

`revoke` means the old password stops working. It does not drop the role and
does not strip its grants, because that role is what the cycle after next will
use, and a role rebuilt from memory is a grant somebody forgets.

## Verify, then publish, then wait, then revoke

The verify is three attempts five seconds apart, not one. `ALTER ROLE` is
immediate on the primary and a reader replica is not the primary, so a verify
routed to a replica can fail once and pass on the next attempt.

The wait is the part people cut. `quiesce_seconds` has to outlast the longest
cache any consumer keeps the credential in, and `consumer_cache_seconds` in
`targets.toml` is where that budget is declared: 300 seconds, against a
default window of 900. `config.load` refuses a file where any target's window
is not longer than the budget. `reporting-db` sets 3600 instead, because its
workers hold a connection for the length of a batch, so the number that
matters there is the batch timeout and not a cache TTL.

Those numbers are a convention in this repo, not a measurement. Nothing here
has sampled a real consumer's refresh behaviour.

After the promote there is no rollback, and the machine does not offer one.
`abort` is not a legal event from `promoted` or `quiesced`. Putting the old
credential back would strand any consumer that had already fetched the new one,
so the only exit is `give_up`, which stops and says a person is needed.

## The dry run reads and nothing else

    rotator plan

prints one line per target: due or not, the age of the live credential, which
user is next, and any blocker. A staged credential from a stopped run is a
blocker rather than something `plan` clears, because the thing that cleans up
after a failure should be the thing a person typed.

The claim that it writes nothing is checked at the boto3 layer, not in a
comment. `tests/test_plan_is_read_only.py` registers a `before-call` handler on
the botocore event system, runs a plan, and compares the operation names that
were actually sent against `READ_ONLY_OPERATIONS`.

The age it reports is the creation date of the version carrying `AWSCURRENT`,
not `describe_secret`'s `LastChangedDate`. `LastChangedDate` moves when a
pending version is written, so it reports a month old password as new the
moment a rotation starts, which is exactly when you are looking at it.

## Two stores, and the publish step is the difference

**Secrets Manager** has staging labels, so the publish is one
`UpdateSecretVersionStage` call and the server makes it atomic. There is no
window where a consumer can read half a rotation.

That call moves `AWSCURRENT` and leaves `AWSPENDING` attached to the same
version. The first version of `promote` here did not know that, so every
finished rotation looked half finished and the next run refused to start.
`promote` is two calls now, and `staged()` separately ignores a pending label
sitting on the version that is already current. Commit `f9fb796` is that fix
and the two tests that hold it.

**Vault KV v2** has versions and no staging labels. A version is a whole
document, not a label you can move, so the pending credential lives in a
`pending` field of the same document and the promote is a write that moves it
into `current`. **What that gives up is the server side publish:** two fields
change in one write instead of one label moving. It is still atomic, because
every write sends `options.cas` with the version it read, so a second rotator
on the same path gets a 400 rather than overwriting the first one's work.

Vault is reached through `urllib`, not `hvac`. Two endpoints are used, both a
GET and a POST of JSON. **What that gives up is hvac's retry and auth
handling,** in exchange for one fewer dependency with its own release cadence.

## One list of targets

`targets.toml` is it. `scripts/render.py` turns it into the two files
Terraform reads:

    terraform/generated/rotation_policy.json   the role's inline policy
    terraform/generated/targets.json           what schedules.tf iterates

Terraform could build both itself with `data.aws_iam_policy_document` and a
variable, and then there would be two lists of targets that have to agree.
**What rendering gives up is changing a schedule in Terraform alone:**
`scripts/render.py` has to run first, and CI fails when the committed output
differs from what the renderer produces now.

Adding a target is therefore four steps, and
[`adding-a-target.md`](docs/runbooks/adding-a-target.md) is all four.

## The IAM policy, and the six question marks

Two `Allow` statements and one `Deny`. No `Allow` statement names `*` as a
resource, which `tests/test_iam.py` asserts.

Secrets Manager appends six random characters to the ARN of every secret, so a
policy cannot name one exactly. The pattern is six single character wildcards:

    arn:aws:secretsmanager:eu-west-1:111122223333:secret:prod/orders/app-??????

A trailing `*` would be shorter and would also match `prod/orders/app-replica`,
which is a different secret this role has no business reading.

`secretsmanager:ListSecrets` is absent, because it takes no resource and
granting it means granting it on everything. Nothing here needs it: the
targets are declared, not discovered. The `Deny` covers `DeleteSecret`,
`PutResourcePolicy` and replication, on `*`, so the role stays one policy
attachment away from nothing.

The KMS grant carries `kms:ViaService`, so the key is usable through Secrets
Manager and not directly.

`terraform/iam.tf` has a `terraform_data` precondition comparing the account id
baked into the rendered ARNs against `aws_caller_identity`. Applying this in
the wrong account otherwise produces a role with permissions on nothing, and
finds out at 03:15 on a Sunday.

## What it will not do

**It will not create a secret or a role.** The first credential is Terraform's
job. A tool that creates one on a typo creates it in the wrong place and then
rotates it happily forever.

**It will not retry itself.** `schedules.tf` sets
`maximum_retry_attempts = 0`. A schedule cannot tell a task that never started
from one that died between promote and revoke, and retrying the second starts a
fresh rotation against a target whose live credential has just changed. **What
that gives up is recovery from a transient failure:** a network blip means a
manual re-run. The dead letter queue is how the invocation becomes visible
instead.

**It does not use `aws_secretsmanager_secret_rotation`.** That resource can
only invoke a Lambda, and the sequence here sleeps for the quiesce window,
which is an hour on `reporting-db` against a fifteen minute Lambda ceiling.
**What that gives up is the console:** `RotationEnabled` stays false on every
secret listed here and the Rotation tab says rotation is not configured, so
anyone auditing through the console will believe it. The compensating answer to
"when did this last rotate" is the `AWSCURRENT` version's creation date, which
is what `rotator plan` prints.

**It will not rotate its own admin credential.** Rotating the credential that
performs rotations needs a second rotator. The honest version of that is a
person with a password manager, once a year.

**`rotator rotate` refuses without `--confirm`.** The thing that invokes it is
a scheduled task and the thing that reads its help is a person at 2am.

## The password is not in the statement

`ALTER ROLE ... WITH PASSWORD` sends whatever it is given in the statement
text, so a server running `log_statement = 'ddl'` or `'all'` writes it to its
own log, where it outlives the rotation that retired it. Postgres also accepts
a pre-computed SCRAM verifier in that position, so that is what it is given:
`rotator/scram.py` derives it here and the server never sees the plaintext.

A verifier in a log is not a credential. Authenticating needs ClientKey and the
verifier carries SHA-256(ClientKey), which does not invert, so what leaks is an
offline guess at a 48 character password from a 70 character alphabet.

The part that took the work is not the derivation, it is matching the server. A
verifier built against the wrong settings leaves a role that cannot log in,
which is the outage this tool exists to prevent, so both settings are read from
the server itself on the same connection as the ALTER:

| Read | Why not from config |
|---|---|
| `password_encryption` | anything but `scram-sha-256` is a different format, so it refuses rather than writes something unusable |
| `scram_iterations` | a server may be moved off 4096, and the wrong count will not authenticate |

Both use `current_setting(..., true)`. `SHOW scram_iterations` raises on any
server below 16, and a raise inside a transaction aborts it, so the ALTER that
followed would fail with "current transaction is aborted" and send whoever is
reading the alert looking in the wrong place.

Checking `log_statement` is still step seven of
[`stopped-after-promote.md`](docs/runbooks/stopped-after-promote.md), because
a server that logged plaintext before this change still has it in the log.

Separately, `rotator/stores/vault.py` has never spoken to a Vault. It sits
behind a `Protocol` in `rotator/ports.py` and is exercised against a hand
written fake. The version number is pre-1.0 for that reason.

`rotator/database.py` was in the same position until 0.14.0 and is not any
more: it runs against a real Postgres 16 in CI on every pull request, through
the live tier described under Tests. Vault is the half that is left.

## Tests

```bash
python3.11 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/python -m pytest -q
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/python scripts/render.py --check
```

156 tests, no AWS account, no Vault, no database, no network, no compiler.
moto stubs Secrets Manager and IAM. Vault, Postgres and the clock are replaced
by `tests/fakes.py`, which is hand written: nothing in this repo was captured
or recorded from a running system.

### The live tier, and what it caught

A fake is only worth what it is faithful to, so
[`tests/test_database_admin_contract.py`](tests/test_database_admin_contract.py)
runs one set of tests twice, against `FakeDatabase` and against a real server,
and both have to agree. It is marked `live` and deselected by default, so the
command above needs neither Docker nor a database:

```bash
docker compose -f docker-compose.test.yml up -d
ROTATOR_TEST_DSN=postgresql://postgres:rotator-local@localhost:55432/rotator_contract \
  .venv/bin/python -m pytest -m live -q
```

The first run disagreed twice, and both were the fake being kinder than the
server: it accepted a role it had never heard of, and a role name with a
semicolon in it. Twenty test sites were seeding one of the two roles and
rotating onto the other, so the suite had been rotating against a server that
could not exist. The fake now refuses both, and those tests seed the pair.

[`tests/test_postgres_live.py`](tests/test_postgres_live.py) holds what only a
server can answer. The one worth naming: Postgres is made to hash a plaintext
password itself, and the verifier `rotator/scram.py` derives from the salt and
iteration count it chose is compared to the one it stored. RFC 7677 proves the
implementation is SCRAM; this proves it is the same SCRAM as the server that
has to accept it.

**A live run under `trust` tests nothing.** A pg_hba line of `trust` accepts
any password, so every assertion about a wrong one being refused passes without
checking anything. The helper reads `pg_hba_file_rules` and those tests skip
with a reason rather than go green; CI sets `scram-sha-256` explicitly and
fails the job if the server reports anything else.

The clock is injected rather than patched, which is why a target with an hour
long quiesce window costs nothing to test and the test can still assert the
window was waited for.

Three groups are worth reading before the rest:

`tests/test_machine_safety.py` walks the transition table. It enumerates every
route, asserts the table is acyclic, asserts `revoked` has exactly one in edge,
and asserts no route containing a failure event reaches it. A transition added
by hand that opens a path from a failure to a revoke fails here without a store
or a database in the room.

`tests/test_rotation_failures.py` drives the same property through a real
rotation: a credential that does not authenticate, a database that refuses the
`ALTER ROLE`, a revoke that fails after the publish. The first of those asserts
`revoke` was never called at all, and that the secret still holds the password
it held before.

`tests/test_secrets_stay_out_of_the_log.py` runs a rotation with a known
password and then greps everything the run produced: the audit lines, the
outcome, its `repr`. `Credential.__repr__` is redacted on purpose, because a
dataclass prints its fields and that object ends up in exception messages and
pytest output.

## Terraform

```bash
cd terraform
terraform fmt -check -recursive
terraform init -backend=false
terraform validate
tflint --recursive
```

`-backend=false`, so it needs no state bucket, takes no lock and uses no
credentials.

Six variables have no default, because none of them has a safe one:
`cluster_arn`, `task_definition_arn`, `task_execution_role_arn`,
`container_name`, `subnet_ids` and `security_group_ids`. The container image
and the task definition are not declared here, because this is not the repo
that owns the cluster.

The scheduler role's `ecs:RunTask` is conditioned on one cluster and its
`iam:PassRole` is limited to two roles. `RunTask` with an unrestricted
`PassRole` would let the scheduler start a task as any role in the account,
including one that reads every secret.

## Running it

```bash
rotator plan                              # all targets, reads only
rotator plan --target orders-db
rotator status --target orders-db
rotator discard orders-db                 # drop what a stopped run staged
rotator rotate --target orders-db --confirm
```

All four need AWS credentials for a Secrets Manager target, or `VAULT_ADDR`
and `VAULT_TOKEN` for a Vault one. `rotate` additionally needs
`ROTATOR_ADMIN_DSN` and `ROTATOR_VERIFY_DSN`, since it is the only one that
opens a database connection. None of the five is read from `targets.toml`, on
purpose.

Exit codes: 0 clean, 1 something was blocked or rolled back, 2 a usage or
config error, 3 a target is in `abandoned` and
[`stopped-after-promote.md`](docs/runbooks/stopped-after-promote.md) applies.
