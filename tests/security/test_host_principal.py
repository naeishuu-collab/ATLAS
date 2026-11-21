from dataclasses import replace

import pytest

from openjarvis.security.host_principal import HostPrincipalAuthority


def test_host_credential_is_verifiable_by_bootstrapped_controller():
    host = HostPrincipalAuthority(b"h" * 32)
    credential = host.issue("host-user", "controller-session")
    controller_authority = HostPrincipalAuthority(b"h" * 32)

    principal = controller_authority.verify(credential)

    assert controller_authority.accepts(principal, session_id="controller-session")
    assert not controller_authority.accepts(principal, session_id="other-session")
    assert not host.accepts(principal)


def test_host_credential_rejects_forgery_expiry_and_revocation():
    now = [1000.0]
    authority = HostPrincipalAuthority(b"h" * 32, ttl=10, clock=lambda: now[0])
    credential = authority.issue("host-user", "controller-session")
    forged = replace(credential, principal_id="forged-host")

    with pytest.raises(PermissionError, match="credential invalid"):
        authority.verify(forged)

    principal = authority.verify(credential)
    authority.revoke(principal)
    assert not authority.accepts(principal)
    with pytest.raises(PermissionError, match="credential revoked"):
        authority.verify(credential)

    now[0] = 1010.0
    with pytest.raises(PermissionError, match="credential expired"):
        HostPrincipalAuthority(b"h" * 32, ttl=10, clock=lambda: now[0]).verify(
            credential
        )
