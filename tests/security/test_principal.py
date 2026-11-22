from dataclasses import replace
from unittest.mock import patch

import pytest

from openjarvis.security.principal import (
    PrincipalCredential,
    TestPrincipalAuthority,
    TrustedPrincipal,
)


def test_signed_test_principal_rejects_forgery_expiry_and_revocation():
    authority = TestPrincipalAuthority(b"test-only-secret", ttl=10)
    credential = authority.issue("principal-a")
    principal = authority.verify(credential)
    assert principal.principal_id == "principal-a"
    with pytest.raises(PermissionError):
        authority.verify(replace(credential, principal_id="principal-b"))
    forged = PrincipalCredential(
        credential.principal_id,
        credential.token_id,
        credential.issued_at,
        credential.expires_at,
        "0" * 64,
    )
    with pytest.raises(PermissionError):
        authority.verify(forged)
    authority.revoke(principal)
    with pytest.raises(PermissionError, match="revoked"):
        authority.verify(credential)
    assert not authority.accepts(principal)
    assert authority.owns(principal)


def test_expired_test_principal_is_not_accepted():
    authority = TestPrincipalAuthority(b"test-only-secret", ttl=10)
    credential = authority.issue("principal-a")
    principal = authority.verify(credential)
    with patch(
        "openjarvis.security.principal.time.time",
        return_value=credential.expires_at,
    ):
        assert not authority.accepts(principal)
        with pytest.raises(PermissionError, match="expired"):
            authority.verify(credential)


def test_principal_cannot_be_forged_into_authority_acceptance():
    authority = TestPrincipalAuthority(b"test-only-secret")
    credential = authority.issue("principal-a")
    principal = authority.verify(credential)
    forged = TrustedPrincipal(
        "principal-b",
        principal.token_id,
        principal.issued_at,
        principal.expires_at,
        authority.source,
        principal._proof,
    )
    assert not authority.accepts(forged)
