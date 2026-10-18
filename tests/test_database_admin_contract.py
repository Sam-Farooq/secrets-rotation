"""One set of tests, run against the fake and against a real Postgres.

`tests/fakes.py` is what the whole suite rotates against, so everything this
tool is known to do is known through it. These tests are the ones that say the
fake is a faithful stand-in rather than a convenient one: each runs twice, once
against `FakeDatabase` and once against `PostgresAdmin` on a live server, and
both have to agree.

The live half is marked `live` and is deselected unless asked for, so the
default run stays offline and needs neither Docker nor a server:

    pytest                  the fake only, no network
    pytest -m live          the real server, needs ROTATOR_TEST_DSN
    pytest -m ""            both
"""

from __future__ import annotations

import live_postgres as live
import pytest
from fakes import FakeDatabase

from rotator.database import PostgresAdmin
from rotator.errors import ProviderError
from rotator.ports import Credential

PASSWORD = "a-password-nobody-would-choose-9f3c"
OTHER = "a-second-password-equally-unlikely-7b2e"


class FakeHarness:
    """The fake, plus the two things a test needs to know about any backend."""

    name = "fake"
    enforces_passwords = True

    def __init__(self):
        self.app_a = "orders_app_a"
        self.app_b = "orders_app_b"
        self.nologin = "orders_reporting"
        self.admin = FakeDatabase(
            {self.app_a: "seed-a", self.app_b: "seed-b", self.nologin: "seed-n"},
            reject=(self.nologin,),
        )

    def setup(self):
        return self

    def teardown(self):
        pass


class LiveHarness:
    name = "live"

    def __init__(self):
        self.roles = None
        self.admin = None

    def setup(self):
        live.psycopg()
        self.roles = live.Roles()
        self.roles.create()
        self.app_a = self.roles.app_a
        self.app_b = self.roles.app_b
        self.nologin = self.roles.nologin
        self.admin = PostgresAdmin(live.dsn(), live.verify_dsn_template())
        self.enforces_passwords = live.password_auth_enforced()
        return self

    def teardown(self):
        if self.roles is not None:
            self.roles.drop()


@pytest.fixture(params=[FakeHarness, pytest.param(LiveHarness, marks=pytest.mark.live)])
def backend(request):
    harness = request.param().setup()
    yield harness
    harness.teardown()


def needs_real_auth(backend):
    if not backend.enforces_passwords:
        pytest.skip(
            "this server's pg_hba uses trust, so a wrong password is accepted "
            "and this assertion would pass without checking anything"
        )


def test_a_password_that_was_set_then_verifies(backend):
    backend.admin.set_password(backend.app_a, PASSWORD)
    assert backend.admin.verify(Credential(backend.app_a, PASSWORD)) is True


def test_a_password_that_was_not_set_does_not_verify(backend):
    needs_real_auth(backend)
    backend.admin.set_password(backend.app_a, PASSWORD)
    assert backend.admin.verify(Credential(backend.app_a, OTHER)) is False


def test_setting_twice_leaves_the_second_password_live(backend):
    backend.admin.set_password(backend.app_a, PASSWORD)
    backend.admin.set_password(backend.app_a, OTHER)
    assert backend.admin.verify(Credential(backend.app_a, OTHER)) is True


def test_the_previous_password_stops_working_after_the_second_set(backend):
    needs_real_auth(backend)
    backend.admin.set_password(backend.app_a, PASSWORD)
    backend.admin.set_password(backend.app_a, OTHER)
    assert backend.admin.verify(Credential(backend.app_a, PASSWORD)) is False


def test_revoke_makes_the_old_password_useless(backend):
    needs_real_auth(backend)
    backend.admin.set_password(backend.app_b, PASSWORD)
    assert backend.admin.verify(Credential(backend.app_b, PASSWORD)) is True
    backend.admin.revoke(backend.app_b)
    assert backend.admin.verify(Credential(backend.app_b, PASSWORD)) is False


def test_the_two_roles_do_not_interfere(backend):
    backend.admin.set_password(backend.app_a, PASSWORD)
    backend.admin.set_password(backend.app_b, OTHER)
    assert backend.admin.verify(Credential(backend.app_a, PASSWORD)) is True
    assert backend.admin.verify(Credential(backend.app_b, OTHER)) is True


def test_a_role_that_cannot_log_in_does_not_verify(backend):
    """The state machine branches on this, so both backends have to agree.

    A NOLOGIN role is not a wrong password and not an unreachable server. It is
    a third thing, and the only honest answer either backend can give is False.
    """
    backend.admin.set_password(backend.nologin, PASSWORD)
    assert backend.admin.verify(Credential(backend.nologin, PASSWORD)) is False


def test_an_unknown_role_raises_rather_than_returning_false(backend):
    with pytest.raises(ProviderError):
        backend.admin.set_password("role_that_was_never_created_8c1d", PASSWORD)


def test_a_role_name_that_is_not_an_identifier_is_refused(backend):
    with pytest.raises(ProviderError):
        backend.admin.set_password("orders_app_a; DROP DATABASE orders", PASSWORD)


def test_revoke_does_not_remove_the_role(backend):
    """Revoke scrambles the password. The role is used again two rotations from
    now, and a role recreated every cycle is a set of grants waiting to be
    forgotten."""
    backend.admin.set_password(backend.app_b, PASSWORD)
    backend.admin.revoke(backend.app_b)
    # Still there to be set again, which is the whole point.
    backend.admin.set_password(backend.app_b, OTHER)
    assert backend.admin.verify(Credential(backend.app_b, OTHER)) is True
