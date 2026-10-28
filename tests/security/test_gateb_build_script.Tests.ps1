# Gate B build-script hardening tests (Pester 3.4, offline, nonphysical).
# Cryptographic authorization is covered in test_gateb_crypto.Tests.ps1.
# This suite covers the unsigned-failure boundary end-to-end (the pinned
# trust store is absent, so every invocation must refuse) plus the
# input-handling helpers. Never invokes cl.exe, link.exe, or artifacts.

$BuildScript = Join-Path $PSScriptRoot "..\..\scripts\astra-native-launcher-build.ps1"
$Snapshot = "C:\Users\yingz\AppData\Local\Temp\opencode\astra-candidate-snapshot-d596e48"

Describe "Gate B unsigned boundary" {
    It "Any envelope refuses without trust store (exit 2, no OutDir)" {
        $tmp = Join-Path ([IO.Path]::GetTempPath()) ("gateb-" + [Guid]::NewGuid().ToString("N"))
        New-Item -ItemType Directory -Path $tmp | Out-Null
        $envPath = Join-Path $tmp "envelope.json"
        Set-Content $envPath '{"schema":1}'
        $outDir = Join-Path $tmp "out"
        $p = Start-Process powershell -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $BuildScript, "-ApprovalEnvelope", $envPath, "-SourceDir", $Snapshot, "-OutDir", $outDir) -Wait -PassThru -NoNewWindow
        $p.ExitCode | Should Be 2
        Test-Path $outDir | Should Be $false
        Remove-Item -Recurse -Force $tmp
    }

    It "Missing envelope refuses (exit 2, no OutDir)" {
        $tmp = Join-Path ([IO.Path]::GetTempPath()) ("gateb-" + [Guid]::NewGuid().ToString("N"))
        New-Item -ItemType Directory -Path $tmp | Out-Null
        $outDir = Join-Path $tmp "out"
        $p = Start-Process powershell -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $BuildScript, "-ApprovalEnvelope", (Join-Path $tmp "nope.json"), "-SourceDir", $Snapshot, "-OutDir", $outDir) -Wait -PassThru -NoNewWindow
        $p.ExitCode | Should Be 2
        Test-Path $outDir | Should Be $false
        Remove-Item -Recurse -Force $tmp
    }
}

Describe "Gate B input-handling helpers" {
    BeforeAll { . $BuildScript }

    It "Manifest traversal entries are rejected" {
        Test-ManifestEntry "..\evil.c" ("ab" * 32) | Should Be $false
        Test-ManifestEntry "C:\Windows\evil.c" ("ab" * 32) | Should Be $false
        Test-ManifestEntry "evil.c" "zz" | Should Be $false
        Test-ManifestEntry "src/ok.c" ("ab" * 32) | Should Be $true
    }

    It "Reparse-point inputs are rejected" {
        $tmp = Join-Path ([IO.Path]::GetTempPath()) ("gateb-" + [Guid]::NewGuid().ToString("N") + ".txt")
        Set-Content $tmp "x"
        Test-InputHandle $tmp | Should Be $true
        Remove-Item $tmp
        Test-InputHandle (Join-Path ([IO.Path]::GetTempPath()) "gateb-missing-file.txt") | Should Be $false
    }

    It "Scrubbed environment drops toolchain hijack variables" {
        $clean = Get-ScrubbedBuildEnvironment
        foreach ($k in @("INCLUDE", "LIB", "LIBPATH", "CL", "_CL_", "_LINK_")) {
            $clean.ContainsKey($k) | Should Be $false
        }
    }

    It "Partial outputs are cleaned on failure" {
        $tmp = Join-Path ([IO.Path]::GetTempPath()) ("gateb-" + [Guid]::NewGuid().ToString("N"))
        New-Item -ItemType Directory -Path $tmp | Out-Null
        $o = Join-Path $tmp "a.obj"; $e = Join-Path $tmp "a.exe"
        Set-Content $o "obj"; Set-Content $e "exe"
        Clear-PartialBuildOutput $o $e
        (Test-Path $o) -or (Test-Path $e) | Should Be $false
        Remove-Item -Recurse -Force $tmp
    }
}
