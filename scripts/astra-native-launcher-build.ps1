<#
.NOT APPROVED 窶・REVIEW REQUEST ONLY.
Astra Native C Launcher build package (Artifact A, standalone C only).

Gate B stays NON-EXECUTABLE until a human trust ceremony provisions
build-authority/trust-roots.json (pinned path below). No approval
record, ID, environment variable, or switch authorizes compilation on
its own. Only RS256 (RSA PKCS#1 v1.5 + SHA-256, .NET built-in) is
accepted; there is no algorithm negotiation.

Exit codes: 0 built+hashed | 2 authorization/provenance-gate refusal |
3 toolchain missing | 4 input failure | 5 compile/link failure.
The built executable is never invoked by this script.
#>
param(
    [string]$ApprovalEnvelope = "",
    [string]$SourceDir = "",
    [string]$OutDir = "",
    [string]$MSVC = "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Tools\MSVC\14.51.36231",
    [string]$SDK = "C:\Program Files (x86)\Windows Kits\10",
    [string]$SDKV = "10.0.26100.0"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function ConvertTo-CanonicalJson($value) {
    if ($value -is [hashtable]) {
        $keys = @($value.Keys | Sort-Object -Culture "" -CaseSensitive)
        $parts = foreach ($k in $keys) {
            (ConvertTo-CanonicalJsonString ([string]$k)) + ":" + (ConvertTo-CanonicalJson $value[$k])
        }
        return "{" + ($parts -join ",") + "}"
    }
    if ($value -is [System.Management.Automation.PSCustomObject]) {
        $keys = @($value.PSObject.Properties | Select-Object -ExpandProperty Name | Sort-Object -Culture "" -CaseSensitive)
        $parts = foreach ($k in $keys) {
            (ConvertTo-CanonicalJsonString ([string]$k)) + ":" + (ConvertTo-CanonicalJson $value.$k)
        }
        return "{" + ($parts -join ",") + "}"
    }
    if ($value -is [System.Collections.IEnumerable] -and $value -isnot [string]) {
        $parts = foreach ($item in $value) { ConvertTo-CanonicalJson $item }
        return "[" + ($parts -join ",") + "]"
    }
    if ($value -is [string]) { return ConvertTo-CanonicalJsonString $value }
    if ($value -is [bool]) { if ($value) { return "true" } else { return "false" } }
    if ($value -is [int] -or $value -is [long]) { return "$value" }
    throw "non-canonical value type"
}

function ConvertTo-CanonicalJsonString([string]$s) {
    $sb = New-Object Text.StringBuilder ('"' )
    foreach ($ch in $s.ToCharArray()) {
        $n = [int]$ch
        if ($ch -eq '"') { [void]$sb.Append('\"') }
        elseif ($ch -eq '\') { [void]$sb.Append('\\') }
        elseif ($ch -eq "`b") { [void]$sb.Append('\b') }
        elseif ($ch -eq "`f") { [void]$sb.Append('\f') }
        elseif ($ch -eq "`n") { [void]$sb.Append('\n') }
        elseif ($ch -eq "`r") { [void]$sb.Append('\r') }
        elseif ($ch -eq "`t") { [void]$sb.Append('\t') }
        elseif ($n -lt 0x20) { [void]$sb.Append(('\u{0:x4}' -f $n)) }
        else { [void]$sb.Append($ch) }
    }
    [void]$sb.Append('"')
    return $sb.ToString()
}

function Test-ManifestEntry([string]$rel, [string]$hash) {
    if ([string]::IsNullOrWhiteSpace($rel)) { return $false }
    if ($rel -match "\.\.") { return $false }
    if ([IO.Path]::IsPathRooted($rel)) { return $false }
    if ($rel -match "^[A-Za-z]:") { return $false }
    if ($rel.Contains(":")) { return $false }
    if ($hash -notmatch "^[0-9A-Fa-f]{64}$") { return $false }
    return $true
}

function Test-ManifestSet([string[]]$rels) {
    if ($null -eq $rels -or $rels.Count -eq 0) { return $false }
    $seen = @{}
    foreach ($rel in $rels) {
        $folded = [string]$rel
        foreach ($key in @($seen.Keys)) {
            if ($key -eq $folded) { return $false }
        }
        $seen[$folded] = $true
    }
    return $true
}

function Test-InputHandle([string]$path) {
    try {
        $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
    } catch { return $false }
    if ($item.PSIsContainer) { return $false }
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        return $false
    }
    return $true
}

function Get-ScrubbedBuildEnvironment {
    $hijack = @("INCLUDE", "LIB", "LIBPATH", "CL", "_CL_", "_LINK_")
    $clean = @{}
    foreach ($entry in (Get-ChildItem Env:)) {
        if ($entry.Name -notin $hijack) { $clean[$entry.Name] = $entry.Value }
    }
    return $clean
}

function Clear-PartialBuildOutput([string]$obj, [string]$exe) {
    foreach ($p in @($obj, $exe)) {
        try {
            if (-not [string]::IsNullOrWhiteSpace($p) -and (Test-Path -LiteralPath $p)) {
                Remove-Item -LiteralPath $p -Force
            }
        } catch { }
    }
}

function Test-EnvelopeText([string]$raw) {
    $deny = { param($c, $d) return @{ ok = $false; code = $c; detail = $d } }
    if ([string]::IsNullOrWhiteSpace($raw) -or $raw.Length -gt 65536) {
        return (& $deny "ENVELOPE_MALFORMED" "envelope missing or oversized")
    }
    $names = @{}
    foreach ($m in ([regex]'"((?:[^"\\]|\\.)*)"\s*:').Matches($raw)) {
        $normalized = $m.Groups[1].Value
        foreach ($u in ([regex]'\\u([0-9A-Fa-f]{4})').Matches($normalized)) {
            $code = [Convert]::ToInt32($u.Groups[1].Value, 16)
            if ($code -lt 128) {
                $normalized = $normalized.Replace($u.Value, [string][char]$code)
            }
        }
        $normalized = $normalized.Replace('\\', '\').Replace('\"', '"')
        if ($names.ContainsKey($normalized)) {
            return (& $deny "ENVELOPE_MALFORMED" "duplicate property: $normalized")
        }
        $names[$normalized] = $true
    }
    try {
        $envelope = $raw | ConvertFrom-Json -ErrorAction Stop
    } catch {
        return (& $deny "ENVELOPE_MALFORMED" "invalid JSON")
    }
    $topKeys = @($envelope.PSObject.Properties | Select-Object -ExpandProperty Name | Sort-Object -Culture "" -CaseSensitive)
    $wantTop = @("algorithm", "kid", "payload", "schema", "signature")
    if (($topKeys -join ",") -cne ($wantTop -join ",")) {
        return (& $deny "ENVELOPE_MALFORMED" "unexpected top-level fields")
    }
    if ($envelope.schema -ne 1) {
        return (& $deny "ENVELOPE_MALFORMED" "unsupported envelope schema")
    }
    if ([string]$envelope.algorithm -cne "RS256") {
        return (& $deny "ALGORITHM_REJECTED" "only RS256 is accepted")
    }
    if ([string]::IsNullOrWhiteSpace([string]$envelope.kid)) {
        return (& $deny "ENVELOPE_MALFORMED" "missing key id")
    }
    try {
        $sig = [Convert]::FromBase64String([string]$envelope.signature)
    } catch {
        return (& $deny "ENVELOPE_MALFORMED" "malformed signature encoding")
    }
    if ($sig.Length -eq 0) {
        return (& $deny "ENVELOPE_MALFORMED" "empty signature")
    }
    $payload = $envelope.payload
    if ($payload -isnot [System.Management.Automation.PSCustomObject]) {
        return (& $deny "ENVELOPE_MALFORMED" "payload must be an object")
    }
    $payloadFields = @("protocolVersion", "approvalId", "issuer", "keyId",
        "operation", "snapshotHash", "scriptHash", "toolchain", "outputDir",
        "authority", "issuedAt", "notBefore", "expiresAt", "revocationRef",
        "replayPolicy", "auditId", "claimDir")
    $gotKeys = @($payload.PSObject.Properties | Select-Object -ExpandProperty Name | Sort-Object -Culture "" -CaseSensitive)
    $wantKeys = @($payloadFields | Sort-Object -Culture "" -CaseSensitive)
    if (($gotKeys -join ",") -cne ($wantKeys -join ",")) {
        return (& $deny "ENVELOPE_MALFORMED" "unexpected payload fields")
    }
    if ([int]$payload.protocolVersion -ne 1) {
        return (& $deny "ENVELOPE_MALFORMED" "unsupported protocol version")
    }
    foreach ($f in @("approvalId", "issuer", "keyId", "operation",
            "snapshotHash", "scriptHash", "outputDir", "authority",
            "revocationRef", "auditId", "claimDir")) {
        if ([string]::IsNullOrWhiteSpace([string]$payload.$f)) {
            return (& $deny "ENVELOPE_MALFORMED" "missing payload field: $f")
        }
    }
    foreach ($t in @("issuedAt", "notBefore", "expiresAt")) {
        $v = $payload.$t
        if (($v -isnot [int]) -and ($v -isnot [long])) {
            return (& $deny "ENVELOPE_MALFORMED" "timestamp must be an integer: $t")
        }
    }
    if ([string]$payload.replayPolicy -cne "single-use") {
        return (& $deny "ENVELOPE_MALFORMED" "unsupported replay policy")
    }
    $tool = $payload.toolchain
    if ($tool -isnot [System.Management.Automation.PSCustomObject]) {
        return (& $deny "ENVELOPE_MALFORMED" "toolchain must be an object")
    }
    $toolKeys = @($tool.PSObject.Properties | Select-Object -ExpandProperty Name | Sort-Object -Culture "" -CaseSensitive)
    if (($toolKeys -join ",") -cne "cl,link,sdk") {
        return (& $deny "ENVELOPE_MALFORMED" "unexpected toolchain fields")
    }
    return @{ ok = $true; code = "OK"; detail = "envelope well-formed"; envelope = $envelope }
}

function Test-SignedApproval($envelope, $store, $actual) {
    $deny = { param($c, $d) return @{ ok = $false; code = $c; detail = $d } }
    if ($store -isnot [hashtable]) {
        return (& $deny "TRUST_STORE_MALFORMED" "trust store must be an object")
    }
    foreach ($k in @("storeVersion", "asOf", "maxAgeSeconds", "revokedApprovals", "keys")) {
        if (-not $store.ContainsKey($k)) {
            return (& $deny "TRUST_STORE_MALFORMED" "missing store field: $k")
        }
    }
    if ([int]$store["storeVersion"] -ne 1) {
        return (& $deny "TRUST_STORE_MALFORMED" "unsupported store version")
    }
    $now = [long]$actual["Now"]
    $asOf = [long]$store["asOf"]
    $maxAge = [long]$store["maxAgeSeconds"]
    if ($asOf -gt $now -or ($now - $asOf) -gt $maxAge) {
        return (& $deny "TRUST_STORE_STALE" "trust store snapshot is stale")
    }
    $kids = @($store["keys"] | Where-Object { $_["kid"] -ceq [string]$envelope["kid"] })
    if ($kids.Count -ne 1) {
        return (& $deny "UNKNOWN_KEY" "key id not uniquely trusted")
    }
    if ([string]$envelope["algorithm"] -cne "RS256") {
        return (& $deny "ALGORITHM_REJECTED" "only RS256 is accepted")
    }
    $key = $kids[0]
    if ([string]$key["algorithm"] -cne "RS256") {
        return (& $deny "ALGORITHM_REJECTED" "key algorithm not accepted")
    }
    try {
        $modulus = [Convert]::FromBase64String([string]$key["modulusB64"])
        $exponent = [Convert]::FromBase64String([string]$key["exponentB64"])
    } catch {
        return (& $deny "TRUST_STORE_MALFORMED" "malformed key material")
    }
    if ($modulus.Length -lt 256 -or $exponent.Length -eq 0) {
        return (& $deny "KEY_REJECTED" "weak key material")
    }
    if ([long]$key["validFrom"] -gt $now -or $now -ge [long]$key["validTo"]) {
        return (& $deny "KEY_EXPIRED" "key outside validity window")
    }
    if ($key["revoked"] -eq $true) {
        return (& $deny "KEY_REVOKED" "key revoked")
    }
    $payload = $envelope["payload"]
    if ([string]$payload["issuer"] -cne [string]$key["issuer"]) {
        return (& $deny "UNKNOWN_ISSUER" "issuer not bound to trusted key")
    }
    if ([string]$payload["keyId"] -cne [string]$key["kid"]) {
        return (& $deny "UNKNOWN_ISSUER" "key id not bound to issuer")
    }
    try {
        $canon = ConvertTo-CanonicalJson $payload
        $sig = [Convert]::FromBase64String([string]$envelope["signature"])
        $rsa = New-Object Security.Cryptography.RSACryptoServiceProvider
        try {
            $rsa.ImportParameters(@{ Modulus = $modulus; Exponent = $exponent })
            $verified = $rsa.VerifyData([Text.Encoding]::UTF8.GetBytes($canon), "SHA256", $sig)
        } finally {
            $rsa.Dispose()
        }
    } catch {
        return (& $deny "SIGNATURE_INVALID" "verification failure")
    }
    if (-not $verified) {
        return (& $deny "SIGNATURE_INVALID" "signature mismatch")
    }
    if ([string]$payload["operation"] -cne "gate-b-build") {
        return (& $deny "OPERATION_MISMATCH" "operation is not gate-b-build")
    }
    if ([string]$payload["snapshotHash"] -ne [string]$actual["SnapshotHash"]) {
        return (& $deny "SNAPSHOT_MISMATCH" "snapshot identity mismatch")
    }
    if ([string]$payload["scriptHash"] -ne [string]$actual["ScriptHash"]) {
        return (& $deny "SCRIPT_MISMATCH" "build script identity mismatch")
    }
    foreach ($k in @("cl", "link", "sdk")) {
        if ([string]$payload["toolchain"][$k] -ne [string]$actual["Toolchain"][$k]) {
            return (& $deny "TOOLCHAIN_MISMATCH" "toolchain pin mismatch: $k")
        }
    }
    if ([string]$payload["outputDir"] -ne [string]$actual["OutDir"]) {
        return (& $deny "OUTPUT_DIR_MISMATCH" "output directory not approved")
    }
    if ([string]$payload["claimDir"] -ne [string]$actual["ClaimDir"]) {
        return (& $deny "CLAIM_DIR_MISMATCH" "claim directory not approved")
    }
    if ($now -lt [long]$payload["notBefore"]) {
        return (& $deny "NOT_YET_VALID" "approval not yet valid")
    }
    if ($now -ge [long]$payload["expiresAt"]) {
        return (& $deny "APPROVAL_EXPIRED" "approval expired")
    }
    if ([string]$payload["approvalId"] -cin @($store["revokedApprovals"])) {
        return (& $deny "APPROVAL_REVOKED" "approval revoked")
    }
    $claimPath = Join-Path ([string]$payload["claimDir"]) ([string]$payload["approvalId"] + ".claim.json")
    if (Test-Path -LiteralPath $claimPath) {
        $verdict = Get-ClaimRecoveryVerdict $claimPath
        return (& $deny "APPROVAL_REUSED" ("approval already consumed (" + $verdict["action"] + ")"))
    }
    return @{ ok = $true; code = "OK"; detail = "authorized"; payload = $payload }
}

function New-ClaimReservation([string]$claimPath, [string]$content) {
    try {
        $stream = [IO.File]::Open($claimPath, [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write, [IO.FileShare]::None)
        try {
            $bytes = [Text.Encoding]::UTF8.GetBytes($content)
            $stream.Write($bytes, 0, $bytes.Length)
        } finally {
            $stream.Dispose()
        }
        return $true
    } catch [IO.IOException] {
        return $false
    }
}

function Set-ClaimState([string]$claimPath, [string]$fromState, [string]$toState) {
    try {
        $claim = Get-Content -LiteralPath $claimPath -Raw -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop
        if ([string]$claim.state -ne $fromState) { return $false }
        $claim.state = $toState
        ($claim | ConvertTo-Json -Depth 8) | Set-Content -LiteralPath $claimPath -Encoding utf8
        return $true
    } catch {
        return $false
    }
}

function Get-ClaimRecoveryVerdict([string]$claimPath) {
    if (-not (Test-Path -LiteralPath $claimPath)) {
        return @{ action = "UNSEEN"; detail = "no claim recorded" }
    }
    try {
        $state = [string](Get-Content -LiteralPath $claimPath -Raw -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop).state
    } catch {
        return @{ action = "QUARANTINE_NEW_APPROVAL"; detail = "unreadable claim ledger" }
    }
    switch ($state) {
        "CLAIMED" { return @{ action = "REQUIRE_NEW_APPROVAL_SAFE"; detail = "reserved; compiler never started" } }
        "BUILD_STARTED" { return @{ action = "REQUIRE_NEW_APPROVAL_QUARANTINE"; detail = "interrupted after start; quarantine outputs" } }
        "BUILD_SUCCEEDED" { return @{ action = "ALREADY_BUILT"; detail = "verify artifact hash or rebuild by new approval" } }
        "BUILD_FAILED" { return @{ action = "REQUIRE_NEW_APPROVAL"; detail = "failed attempt consumed the approval" } }
        default { return @{ action = "QUARANTINE_NEW_APPROVAL"; detail = "unknown claim state: $state" } }
    }
}

function Invoke-GateBBuild {
    foreach ($required in @($ApprovalEnvelope, $SourceDir, $OutDir)) {
        if ([string]::IsNullOrWhiteSpace($required)) {
            Write-Host "GATE_B_REFUSED APPROVAL_MALFORMED (missing invocation input)"
            return 2
        }
    }
    $selfHash = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash
    $storePath = Join-Path (Split-Path $PSCommandPath -Parent) "..\build-authority\trust-roots.json"
    if (-not (Test-Path -LiteralPath $storePath)) {
        Write-Host "GATE_B_REFUSED TRUST_STORE_MISSING (no trust roots provisioned)"
        return 2
    }
    $textResult = Test-EnvelopeText (Get-Content -LiteralPath $ApprovalEnvelope -Raw)
    if (-not $textResult["ok"]) {
        Write-Host ("GATE_B_REFUSED " + $textResult["code"] + " " + $textResult["detail"])
        return 2
    }
    $storeRaw = Get-Content -LiteralPath $storePath -Raw | ConvertFrom-Json
    $store = @{}
    foreach ($prop in $storeRaw.PSObject.Properties) { $store[$prop.Name] = $prop.Value }
    $store["keys"] = @($store["keys"] | ForEach-Object {
        $keyRecord = @{}
        foreach ($prop in $_.PSObject.Properties) { $keyRecord[$prop.Name] = $prop.Value }
        $keyRecord
    })
    $manifestPath = Join-Path $SourceDir "MANIFEST.sha256"
    $manifestHash = ""
    if (Test-Path -LiteralPath $manifestPath) {
        $manifestHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash
    }
    $cl = Join-Path $MSVC "bin\Hostx64\x64\cl.exe"
    $link = Join-Path $MSVC "bin\Hostx64\x64\link.exe"
    $actualTool = @{ cl = ""; link = ""; sdk = $SDKV }
    if ((Test-Path -LiteralPath $cl) -and (Test-Path -LiteralPath $link)) {
        $actualTool["cl"] = (Get-Item -LiteralPath $cl).VersionInfo.FileVersion
        $actualTool["link"] = (Get-Item -LiteralPath $link).VersionInfo.FileVersion
    }
    try { $canonOut = [IO.Path]::GetFullPath($OutDir) } catch { $canonOut = $OutDir }
    $claimDir = [string]$textResult["envelope"].payload.claimDir
    try { $canonClaim = [IO.Path]::GetFullPath($claimDir) } catch { $canonClaim = $claimDir }
    $envelope = @{
        kid = [string]$textResult["envelope"].kid
        algorithm = [string]$textResult["envelope"].algorithm
        signature = [string]$textResult["envelope"].signature
        payload = @{}
    }
    foreach ($prop in $textResult["envelope"].payload.PSObject.Properties) {
        $envelope["payload"][$prop.Name] = $prop.Value
    }
    $toolPayload = @{}
    foreach ($prop in $envelope["payload"]["toolchain"].PSObject.Properties) {
        $toolPayload[$prop.Name] = [string]$prop.Value
    }
    $envelope["payload"]["toolchain"] = $toolPayload
    $decision = Test-SignedApproval $envelope $store @{
        SnapshotHash = $manifestHash; ScriptHash = $selfHash
        Toolchain    = $actualTool; OutDir = $canonOut; ClaimDir = $canonClaim
        Now          = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    }
    if (-not $decision["ok"]) {
        Write-Host ("GATE_B_REFUSED " + $decision["code"] + " " + $decision["detail"])
        return 2
    }
    if ((Test-Path -LiteralPath $OutDir) -and (@(Get-ChildItem -LiteralPath $OutDir -Force).Count -gt 0)) {
        Write-Host "GATE_B_REFUSED OUTPUT_DIR_NOT_EMPTY (refusing to overwrite)"
        return 4
    }
    $claimPath = Join-Path $canonClaim ([string]$envelope["payload"]["approvalId"] + ".claim.json")
    $reserveContent = (@{ approvalId = [string]$envelope["payload"]["approvalId"]; state = "CLAIMED";
        snapshotHash = $manifestHash; scriptHash = $selfHash;
        at = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() } | ConvertTo-Json)
    if (-not (New-ClaimReservation $claimPath $reserveContent)) {
        $verdict = Get-ClaimRecoveryVerdict $claimPath
        Write-Host ("GATE_B_REFUSED APPROVAL_REUSED (" + $verdict["action"] + ")")
        return 2
    }
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
    $log = Join-Path $OutDir ("build-" + [string]$envelope["payload"]["approvalId"] + ".log")
    function Log($m) { $m | Tee-Object -FilePath $log -Append | Out-Host }
    $savedEnv = @{}
    try {
        Log ("APPROVAL=" + [string]$envelope["payload"]["approvalId"] + " ISSUER=" + [string]$envelope["payload"]["issuer"])
        Log ("CL_VERSION=" + $actualTool["cl"] + " LINK_VERSION=" + $actualTool["link"])
        $expected = @{}
        $seenRels = @()
        foreach ($line in (Get-Content -LiteralPath $manifestPath)) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            $p = $line -split "  "
            if ($p.Count -lt 2) { Log "MANIFEST_MALFORMED"; return 4 }
            if (-not (Test-ManifestEntry $p[1] $p[0])) { Log "MANIFEST_ENTRY_REJECTED=$($p[1])"; return 4 }
            $expected[$p[1]] = $p[0]
            $seenRels += $p[1]
        }
        if (-not (Test-ManifestSet $seenRels)) { Log "MANIFEST_COLLISION (case-insensitive duplicate)"; return 4 }
        foreach ($rel in $expected.Keys) {
            $p = Join-Path $SourceDir $rel
            if (-not (Test-InputHandle $p)) { Log "INPUT_REJECTED=$rel"; return 4 }
            $h = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash
            if ($h -ne $expected[$rel]) { Log "HASH_MISMATCH=$rel"; return 4 }
        }
        Log "PROVENANCE_OK files=$($expected.Count)"
        foreach ($entry in (Get-ChildItem Env:)) { $savedEnv[$entry.Name] = $entry.Value }
        foreach ($k in @("INCLUDE", "LIB", "LIBPATH", "CL", "_CL_", "_LINK_")) {
            Remove-Item ("Env:\" + $k) -ErrorAction SilentlyContinue
        }
        $src = Join-Path $SourceDir "third-party/codex-security-poc/native_appcontainer_launcher.c"
        $obj = Join-Path $OutDir "native_appcontainer_launcher.obj"
        $exe = Join-Path $OutDir "astra_native_launcher.exe"
        $inc = @("$MSVC\include", "$SDK\Include\$SDKV\ucrt",
            "$SDK\Include\$SDKV\shared", "$SDK\Include\$SDKV\um")
        $lib = @("$MSVC\lib\x64", "$SDK\Lib\$SDKV\ucrt\x64",
            "$SDK\Lib\$SDKV\um\x64")
        $clArgs = @("/nologo", "/c", "/W4", "/O2", "/MT", "/DUNICODE",
            "/D_UNICODE", "/DNDEBUG") +
            ($inc | ForEach-Object { "/I`"$_`"" }) +
            @("/Fo`"$obj`"", "`"$src`"")
        Log "CL_CMDLINE=cl.exe $($clArgs -join ' ')"
        $clProc = Start-Process -FilePath $cl -ArgumentList $clArgs -Wait -PassThru -NoNewWindow
        Log "CL_EXIT=$($clProc.ExitCode)"
        if (-not (Set-ClaimState $claimPath "CLAIMED" "BUILD_STARTED")) {
            Log "CLAIM_TRANSITION_UNEXPECTED (staying fail-closed)"
        }
        if ($clProc.ExitCode -ne 0) {
            Set-ClaimState $claimPath "BUILD_STARTED" "BUILD_FAILED" | Out-Null
            Clear-PartialBuildOutput $obj $exe; return 5
        }
        $linkArgs = @("/NOLOGO", "/OUT:`"$exe`"", "/MACHINE:X64",
            "/SUBSYSTEM:CONSOLE", "/ENTRY:wmainCRTStartup", "/INCREMENTAL:NO",
            "/Brepro", "/DYNAMICBASE", "/NXCOMPAT", "/RELEASE", "/OPT:REF",
            "/OPT:ICF") +
            ($lib | ForEach-Object { "/LIBPATH:`"$_`"" }) +
            @("`"$obj`"", "advapi32.lib", "userenv.lib", "kernel32.lib")
        Log "LINK_CMDLINE=link.exe $($linkArgs -join ' ')"
        $linkProc = Start-Process -FilePath $link -ArgumentList $linkArgs -Wait -PassThru -NoNewWindow
        Log "LINK_EXIT=$($linkProc.ExitCode)"
        if ($linkProc.ExitCode -ne 0) {
            Set-ClaimState $claimPath "BUILD_STARTED" "BUILD_FAILED" | Out-Null
            Clear-PartialBuildOutput $obj $exe; return 5
        }
        $sha = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
        $len = (Get-Item -LiteralPath $exe).Length
        Log "ARTIFACT=$exe BYTES=$len SHA256=$sha"
        Set-ClaimState $claimPath "BUILD_STARTED" "BUILD_SUCCEEDED" | Out-Null
        "ARTIFACT_SHA256=$sha BYTES=$len APPROVAL=$([string]$envelope['payload']['approvalId'])" |
            Set-Content (Join-Path $OutDir ("ARTIFACT." + [string]$envelope["payload"]["approvalId"] + ".sha256"))
        Log "DONE (no execution performed)"
        return 0
    } finally {
        foreach ($entry in (Get-ChildItem Env:)) {
            if (-not $savedEnv.ContainsKey($entry.Name)) {
                Remove-Item ("Env:\" + $entry.Name) -ErrorAction SilentlyContinue
            }
        }
        foreach ($k in $savedEnv.Keys) {
            Set-Item ("Env:\" + $k) $savedEnv[$k] -ErrorAction SilentlyContinue
        }
    }
}

if ($MyInvocation.InvocationName -ne ".") {
    exit (Invoke-GateBBuild)
}
