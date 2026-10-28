# Gate B cryptographic boundary tests (Pester 3.4, offline, nonphysical).
# Synthetic RSA keys only, generated per run in TEMP and discarded.
# Never invokes cl.exe, link.exe, or native artifacts.

$BuildScript = Join-Path $PSScriptRoot "..\..\scripts\astra-native-launcher-build.ps1"

Describe "Gate B cryptographic boundary" {
    BeforeAll {
        . $BuildScript
        $script:TestKey = New-Object System.Security.Cryptography.RSACryptoServiceProvider(2048)
        $script:TestParams = $script:TestKey.ExportParameters($false)
    }
    AfterAll { $script:TestKey.Dispose() }

    function New-TestStore($overrides = @{}) {
        $store = @{
            storeVersion = 1
            asOf = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
            maxAgeSeconds = 604800
            revokedApprovals = @()
            keys = @(@{
                kid = "TEST-K1"; issuer = "TEST-AUTHORITY"; algorithm = "RS256"
                modulusB64 = [Convert]::ToBase64String($script:TestParams.Modulus)
                exponentB64 = [Convert]::ToBase64String($script:TestParams.Exponent)
                validFrom = 1000; validTo = 9999999999; revoked = $false
                auditRef = "AUD-KEY"
            })
        }
        foreach ($k in $overrides.Keys) { $store[$k] = $overrides[$k] }
        return $store
    }

    function New-TestPayload($overrides = @{}) {
        $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        $p = @{
            protocolVersion = 1; approvalId = "GATEB-CRYPTO-001"; issuer = "TEST-AUTHORITY"
            keyId = "TEST-K1"; operation = "gate-b-build"
            snapshotHash = "aa"; scriptHash = "bb"
            toolchain = @{ cl = "c"; link = "l"; sdk = "s" }
            outputDir = "o"; authority = "TEST-BUILD-AUTHORITY"
            issuedAt = ($now - 60); notBefore = ($now - 60); expiresAt = ($now + 3600)
            revocationRef = "store"; replayPolicy = "single-use"; auditId = "AUD-1"
            claimDir = "cd"
        }
        foreach ($k in $overrides.Keys) { $p[$k] = $overrides[$k] }
        return $p
    }

    function New-SignedEnvelope($payload) {
        $canon = ConvertTo-CanonicalJson $payload
        $sig = $script:TestKey.SignData([Text.Encoding]::UTF8.GetBytes($canon), "SHA256")
        return @{
            schema = 1; kid = "TEST-K1"; algorithm = "RS256"
            payload = $payload; signature = [Convert]::ToBase64String($sig)
        }
    }

    function New-ValidActual($overrides = @{}) {
        $a = @{
            SnapshotHash = "aa"; ScriptHash = "bb"
            Toolchain = @{ cl = "c"; link = "l"; sdk = "s" }
            OutDir = "o"; ClaimDir = "cd"; Now = ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())
        }
        foreach ($k in $overrides.Keys) { $a[$k] = $overrides[$k] }
        return $a
    }

    It "Missing trust store refuses end-to-end without side effects" {
        $tmp = Join-Path ([IO.Path]::GetTempPath()) ("gatebc-" + [Guid]::NewGuid().ToString("N"))
        New-Item -ItemType Directory -Path $tmp | Out-Null
        $envelope = New-SignedEnvelope (New-TestPayload)
        $envPath = Join-Path $tmp "env.json"
        ($envelope | ConvertTo-Json -Depth 8) | Set-Content $envPath -Encoding utf8
        $outDir = Join-Path $tmp "out"
        $p = Start-Process powershell -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $BuildScript, "-ApprovalEnvelope", $envPath, "-SourceDir", $tmp, "-OutDir", $outDir) -Wait -PassThru -NoNewWindow
        $p.ExitCode | Should Be 2
        Test-Path $outDir | Should Be $false
        Remove-Item -Recurse -Force $tmp
    }

    It "Unknown issuer is rejected" {
        $envelope = New-SignedEnvelope (New-TestPayload @{ issuer = "FORGED-AUTHORITY" })
        $r = Test-SignedApproval $envelope (New-TestStore) (New-ValidActual)
        $r.ok | Should Be $false
        $r.code | Should Be "UNKNOWN_ISSUER"
    }

    It "Caller-supplied public key is rejected as unknown field" {
        $envelope = New-SignedEnvelope (New-TestPayload)
        $envelope["payload"]["publicKey"] = "attacker-key"
        $raw = ($envelope | ConvertTo-Json -Depth 8)
        $r = Test-EnvelopeText $raw
        $r.ok | Should Be $false
    }

    It "Wrong signature is rejected" {
        $envelope = New-SignedEnvelope (New-TestPayload)
        $sig = [Convert]::FromBase64String($envelope["signature"])
        $sig[0] = $sig[0] -bxor 1
        $envelope["signature"] = [Convert]::ToBase64String($sig)
        $r = Test-SignedApproval $envelope (New-TestStore) (New-ValidActual)
        $r.ok | Should Be $false
        $r.code | Should Be "SIGNATURE_INVALID"
    }

    It "Modified payload is rejected" {
        $envelope = New-SignedEnvelope (New-TestPayload)
        $envelope["payload"]["outputDir"] = "evil-dir"
        $r = Test-SignedApproval $envelope (New-TestStore) (New-ValidActual)
        $r.ok | Should Be $false
        $r.code | Should Be "SIGNATURE_INVALID"
    }

    It "Duplicate JSON properties are rejected" {
        $raw = '{"schema":1,"schema":1,"kid":"x","algorithm":"RS256","payload":{},"signature":"AA=="}'
        $r = Test-EnvelopeText $raw
        $r.ok | Should Be $false
        $r.code | Should Be "ENVELOPE_MALFORMED"
    }

    It "Unsupported algorithm is rejected" {
        $envelope = New-SignedEnvelope (New-TestPayload)
        $envelope["algorithm"] = "none"
        $r = Test-SignedApproval $envelope (New-TestStore) (New-ValidActual)
        $r.ok | Should Be $false
        $r.code | Should Be "ALGORITHM_REJECTED"
    }

    It "Expired approval is rejected" {
        $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        $envelope = New-SignedEnvelope (New-TestPayload @{ issuedAt = ($now - 200); notBefore = ($now - 200); expiresAt = ($now - 1) })
        $r = Test-SignedApproval $envelope (New-TestStore) (New-ValidActual @{ Now = $now })
        $r.ok | Should Be $false
        $r.code | Should Be "APPROVAL_EXPIRED"
    }

    It "Not-yet-valid approval is rejected" {
        $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        $envelope = New-SignedEnvelope (New-TestPayload @{ issuedAt = ($now + 10); notBefore = ($now + 10); expiresAt = ($now + 3600) })
        $r = Test-SignedApproval $envelope (New-TestStore) (New-ValidActual @{ Now = $now })
        $r.ok | Should Be $false
        $r.code | Should Be "NOT_YET_VALID"
    }

    It "Revoked key is rejected" {
        $store = New-TestStore
        $store["keys"][0]["revoked"] = $true
        $envelope = New-SignedEnvelope (New-TestPayload)
        $r = Test-SignedApproval $envelope $store (New-ValidActual)
        $r.ok | Should Be $false
        $r.code | Should Be "KEY_REVOKED"
    }

    It "Revoked approval is rejected" {
        $store = New-TestStore @{ revokedApprovals = @("GATEB-CRYPTO-001") }
        $envelope = New-SignedEnvelope (New-TestPayload)
        $r = Test-SignedApproval $envelope $store (New-ValidActual)
        $r.ok | Should Be $false
        $r.code | Should Be "APPROVAL_REVOKED"
    }

    It "Stale trust store is rejected" {
        $store = New-TestStore @{ asOf = 1000; maxAgeSeconds = 60 }
        $envelope = New-SignedEnvelope (New-TestPayload)
        $r = Test-SignedApproval $envelope $store (New-ValidActual)
        $r.ok | Should Be $false
        $r.code | Should Be "TRUST_STORE_STALE"
    }

    It "Wrong bindings are rejected" {
        $envelope = New-SignedEnvelope (New-TestPayload)
        $r = Test-SignedApproval $envelope (New-TestStore) (New-ValidActual @{ SnapshotHash = "zz" })
        $r.ok | Should Be $false
        $r.code | Should Be "SNAPSHOT_MISMATCH"
    }

    It "Concurrent claims admit exactly one winner" {
        $dir = Join-Path ([IO.Path]::GetTempPath()) ("gatebc-" + [Guid]::NewGuid().ToString("N"))
        New-Item -ItemType Directory -Path $dir | Out-Null
        $claim = Join-Path $dir "race.claim.json"
        $jobs = 1..4 | ForEach-Object {
            Start-Job -ScriptBlock {
                param($c)
                try {
                    $s = [IO.File]::Open($c, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
                    $s.Dispose()
                    return $true
                } catch { return $false }
            } -ArgumentList $claim
        }
        $wins = @($jobs | Wait-Job | Receive-Job | Where-Object { $_ -eq $true }).Count
        $jobs | Remove-Job -Force
        Remove-Item -Recurse -Force $dir
        $wins | Should Be 1
    }

    It "Corrupt claim blocks replay (fail closed)" {
        $dir = Join-Path ([IO.Path]::GetTempPath()) ("gatebc-" + [Guid]::NewGuid().ToString("N"))
        New-Item -ItemType Directory -Path $dir | Out-Null
        Set-Content (Join-Path $dir "GATEB-CRYPTO-001.claim.json") "garbage{{{"
        $envelope = New-SignedEnvelope (New-TestPayload @{ claimDir = $dir })
        $r = Test-SignedApproval $envelope (New-TestStore) (New-ValidActual @{ ClaimDir = $dir })
        $r.ok | Should Be $false
        $r.code | Should Be "APPROVAL_REUSED"
        Remove-Item -Recurse -Force $dir
    }

    It "Valid envelope authorizes at validation level (no compiler)" {
        $dir = Join-Path ([IO.Path]::GetTempPath()) ("gatebc-" + [Guid]::NewGuid().ToString("N"))
        New-Item -ItemType Directory -Path $dir | Out-Null
        $envelope = New-SignedEnvelope (New-TestPayload @{ claimDir = $dir })
        $r = Test-SignedApproval $envelope (New-TestStore) (New-ValidActual @{ ClaimDir = $dir })
        $r.ok | Should Be $true
        $r.code | Should Be "OK"
        Remove-Item -Recurse -Force $dir
    }

    It "Reservation admits one winner and transitions forward only" {
        $dir = Join-Path ([IO.Path]::GetTempPath()) ("gatebc-" + [Guid]::NewGuid().ToString("N"))
        New-Item -ItemType Directory -Path $dir | Out-Null
        $claim = Join-Path $dir "a.claim.json"
        (Get-ClaimRecoveryVerdict $claim).action | Should Be "UNSEEN"
        New-ClaimReservation $claim '{"state":"CLAIMED"}' | Should Be $true
        New-ClaimReservation $claim '{"state":"CLAIMED"}' | Should Be $false
        Set-ClaimState $claim "CLAIMED" "BUILD_STARTED" | Should Be $true
        Set-ClaimState $claim "CLAIMED" "BUILD_SUCCEEDED" | Should Be $false
        Set-ClaimState $claim "BUILD_STARTED" "BUILD_SUCCEEDED" | Should Be $true
        (Get-ClaimRecoveryVerdict $claim).action | Should Be "ALREADY_BUILT"
        Remove-Item -Recurse -Force $dir
    }

    It "Crash leftovers deny reuse with classified verdicts" {
        $dir = Join-Path ([IO.Path]::GetTempPath()) ("gatebc-" + [Guid]::NewGuid().ToString("N"))
        New-Item -ItemType Directory -Path $dir | Out-Null
        $c1 = Join-Path $dir "c1.claim.json"; $c2 = Join-Path $dir "c2.claim.json"
        $c3 = Join-Path $dir "c3.claim.json"; $c4 = Join-Path $dir "c4.claim.json"
        New-ClaimReservation $c1 '{"state":"CLAIMED"}' | Should Be $true
        New-ClaimReservation $c2 '{"state":"BUILD_STARTED"}' | Should Be $true
        New-ClaimReservation $c3 '{"state":"BUILD_FAILED"}' | Should Be $true
        Set-Content $c4 "corrupt{{{"
        (Get-ClaimRecoveryVerdict $c1).action | Should Be "REQUIRE_NEW_APPROVAL_SAFE"
        (Get-ClaimRecoveryVerdict $c2).action | Should Be "REQUIRE_NEW_APPROVAL_QUARANTINE"
        (Get-ClaimRecoveryVerdict $c3).action | Should Be "REQUIRE_NEW_APPROVAL"
        (Get-ClaimRecoveryVerdict $c4).action | Should Be "QUARANTINE_NEW_APPROVAL"
        $envelope = New-SignedEnvelope (New-TestPayload @{ claimDir = $dir; approvalId = "CRASH-1" })
        Set-Content (Join-Path $dir "CRASH-1.claim.json") '{"state":"BUILD_STARTED"}'
        $r = Test-SignedApproval $envelope (New-TestStore) (New-ValidActual @{ ClaimDir = $dir })
        $r.ok | Should Be $false
        $r.code | Should Be "APPROVAL_REUSED"
        Remove-Item -Recurse -Force $dir
    }

    It "Cross-process reservation race admits exactly one winner" {
        $dir = Join-Path ([IO.Path]::GetTempPath()) ("gatebc-" + [Guid]::NewGuid().ToString("N"))
        New-Item -ItemType Directory -Path $dir | Out-Null
        $claim = Join-Path $dir "race.claim.json"
        $jobs = 1..4 | ForEach-Object {
            Start-Job -ScriptBlock {
                param($s, $c)
                . $s
                return (New-ClaimReservation $c '{"state":"CLAIMED"}')
            } -ArgumentList $BuildScript, $claim
        }
        $wins = @($jobs | Wait-Job | Receive-Job | Where-Object { $_ -eq $true }).Count
        $jobs | Remove-Job -Force
        Remove-Item -Recurse -Force $dir
        $wins | Should Be 1
    }

    It "Unicode payload round-trips through canonical form" {
        $dir = Join-Path ([IO.Path]::GetTempPath()) ("gatebc-" + [Guid]::NewGuid().ToString("N"))
        New-Item -ItemType Directory -Path $dir | Out-Null
        $envelope = New-SignedEnvelope (New-TestPayload @{ claimDir = $dir; auditId = "監査-🎯-test" })
        $r = Test-SignedApproval $envelope (New-TestStore) (New-ValidActual @{ ClaimDir = $dir })
        $r.ok | Should Be $true
        Remove-Item -Recurse -Force $dir
    }

    It "Escape-sequence duplicates are rejected" {
        $envelope = New-SignedEnvelope (New-TestPayload)
        $raw = ($envelope | ConvertTo-Json -Depth 8)
        $raw = $raw -replace '"kid"', '"kid","\u006b\u0069\u0064"'
        $raw = $raw -replace '"TEST-K1",', '"TEST-K1","evil",'
        $r = Test-EnvelopeText $raw
        $r.ok | Should Be $false
        $r.code | Should Be "ENVELOPE_MALFORMED"
    }

    It "Case-variant top-level fields are rejected" {
        $envelope = New-SignedEnvelope (New-TestPayload)
        $raw = ($envelope | ConvertTo-Json -Depth 8) -replace '"schema"', '"Schema"'
        $r = Test-EnvelopeText $raw
        $r.ok | Should Be $false
        $r.code | Should Be "ENVELOPE_MALFORMED"
    }

    It "Trailing garbage is rejected" {
        $envelope = New-SignedEnvelope (New-TestPayload)
        $raw = ($envelope | ConvertTo-Json -Depth 8) + "TRAIL"
        $r = Test-EnvelopeText $raw
        $r.ok | Should Be $false
        $r.code | Should Be "ENVELOPE_MALFORMED"
    }

    It "Nested unexpected objects are rejected" {
        $envelope = New-SignedEnvelope (New-TestPayload)
        $envelope["payload"]["extra"] = @{ nested = @(1, 2) }
        $raw = ($envelope | ConvertTo-Json -Depth 8)
        $r = Test-EnvelopeText $raw
        $r.ok | Should Be $false
        $r.code | Should Be "ENVELOPE_MALFORMED"
    }

    It "Non-integer timestamps are rejected" {
        $envelope = New-SignedEnvelope (New-TestPayload)
        $raw = ($envelope | ConvertTo-Json -Depth 8) -replace '"expiresAt":\s+\d+', '"expiresAt": 1.5'
        $r = Test-EnvelopeText $raw
        $r.ok | Should Be $false
        $r.code | Should Be "ENVELOPE_MALFORMED"
    }

    It "Weak RSA keys are rejected" {
        $weak = New-Object System.Security.Cryptography.RSACryptoServiceProvider(1024)
        try {
            $wp = $weak.ExportParameters($false)
            $store = New-TestStore
            $store["keys"][0]["modulusB64"] = [Convert]::ToBase64String($wp.Modulus)
            $store["keys"][0]["exponentB64"] = [Convert]::ToBase64String($wp.Exponent)
            $envelope = New-SignedEnvelope (New-TestPayload)
            $r = Test-SignedApproval $envelope $store (New-ValidActual)
            $r.ok | Should Be $false
            $r.code | Should Be "KEY_REJECTED"
        } finally { $weak.Dispose() }
    }

    It "Stream-suffixed manifest entries are rejected" {
        Test-ManifestEntry "out:evil" ("ab" * 32) | Should Be $false
        Test-ManifestEntry "file.txt:Zone.Identifier" ("ab" * 32) | Should Be $false
    }

    It "Case-colliding manifest sets are rejected" {
        Test-ManifestSet @("src/ok.c", "SRC/OK.C") | Should Be $false
        Test-ManifestSet @("src/ok.c", "src/other.c") | Should Be $true
    }

    It "Post-exit crash leftovers quarantine with outputs present" {
        $dir = Join-Path ([IO.Path]::GetTempPath()) ("gatebc-" + [Guid]::NewGuid().ToString("N"))
        New-Item -ItemType Directory -Path $dir | Out-Null
        $claim = Join-Path $dir "x.claim.json"
        New-ClaimReservation $claim '{"state":"CLAIMED"}' | Should Be $true
        Set-ClaimState $claim "CLAIMED" "BUILD_STARTED" | Should Be $true
        Set-Content (Join-Path $dir "native_appcontainer_launcher.obj") "partial"
        (Get-ClaimRecoveryVerdict $claim).action | Should Be "REQUIRE_NEW_APPROVAL_QUARANTINE"
        Set-ClaimState $claim "MISSING" "BUILD_FAILED" | Should Be $false
        Remove-Item -Recurse -Force $dir
    }

    It "Locked outputs do not break cleanup tolerance" {
        $dir = Join-Path ([IO.Path]::GetTempPath()) ("gatebc-" + [Guid]::NewGuid().ToString("N"))
        New-Item -ItemType Directory -Path $dir | Out-Null
        $o = Join-Path $dir "a.obj"
        Set-Content $o "obj"
        $lock = [IO.File]::Open($o, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
        try {
            { Clear-PartialBuildOutput $o (Join-Path $dir "missing.exe") } | Should Not Throw
        } finally { $lock.Dispose() }
        Remove-Item -Recurse -Force $dir
    }
}
