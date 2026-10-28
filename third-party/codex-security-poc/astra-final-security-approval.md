# JARVIS Astra — Consolidated Security Approval Package

文書状態: **DRAFT / EVIDENCE PACKAGE ONLY / NOT SUBMITTED**  
作成日: 2026-10-09  
対象: `C:\Users\yingz\.codex\worktrees\astra-continuation\JARVIS-Sol`  
Branch: `codex/astra-continuation`  
HEAD: `d596e482c50982cc79c707c7d9fb50d051fcaaed`

この文書は、AppContainer、Rust/RLM RPC、Cloud Egressの承認前状態を一つにまとめる。承認、ポリシー変更、ビルド、Native実行、Production配線はこの文書によって許可されない。

## 1. Verified evidence

### 1.1 Worktree

- Codex Worktree: `C:\Users\yingz\.codex\worktrees\astra-continuation\JARVIS-Sol`
- OpenCode Worktree: `C:\Users\yingz\.codex\worktrees\astra-opencode\JARVIS-Sol`
- 両方のHEADは上記の期待値と一致する。
- Codex branchは `codex/astra-continuation`、OpenCode branchは `opencode/cloud-privacy`。
- Codex側の未追跡ファイルは既知のOpenCode残置ファイルと `tools/` 成果物のみ。既知範囲外の変更は確認されていない。
- OpenCode側は読み取りのみで扱い、変更していない。

### 1.2 既に確認できる安全境界

- RLM Workerは、restricted Python namespace、明示的な capability grant、HostLLMBroker経由の `llm_query` / `llm_batch`、RequestLedger、`UNKNOWN_OUTCOME` quarantineを持つ。
- Workerへ `Agent`、`Engine`、`ToolExecutor`、任意のhost callback、任意のhost objectを渡す設計は確認されていない。
- これはPython/RPC境界の証拠であり、OS-level filesystem/process isolationの証拠ではない。
- Cloud privacy側の authorizer、egress guard、dispatch ledger、capability router、provider catalogは設計・静的成果物として存在するが、Productionの13 egress経路には未配線である。
- LLM出力はuntrusted proposalであり、Safety Authority、capability grant、dispatch ledgerを発行できない。

## 2. Artifact inventory

### 2.1 Codex-owned PoC and package

| Artifact | SHA-256 | Owner / evidence | Current limitation |
|---|---|---|---|
| `tools/security_poc/astra_appcontainer_proof.py` | `02337F0EE46633FB0BE66D1EE9AF937CFEA38EF80AA3D080C002BE26BFF5F6FA` | Codex PoC | Native execution and AppContainer isolation are not proven |
| `tools/security_poc/native_appcontainer_launcher.c` | `DA66889D38F5D82B78D5AE0134FA8F96FF2AF44E011242F7A35EDF8EA4861081` | Codex PoC | Current execution is blocked by Windows Application Control |
| `tools/security_poc/windows_policy_approval_package.md` | `E52E9637C2F8BADD42F346B74F4DC69FE0116A61F85B064B69BE5247D9F61618` | Codex evidence package | Not submitted; owner and approval remain unknown |

The Native launcher contains a PoC-only diagnostic correction: its reported creation flags now reflect the `no-suspend` option and the same flags are passed to `CreateProcessW`. This does not establish a successful launch or identify Error 203.

### 2.2 OpenCode-owned documents

| Artifact | SHA-256 | Ownership / status |
|---|---|---|
| `docs/astra-egress-integration-plan.md` | `87D331041F2DC9A20BB8928386FCDE1FC6AE295757C91BF14A451E9D98873306` | OpenCode; DESIGN, Production wiring not started |
| `docs/astra-rust-build-approval-request.md` | `A6A3F5EC58EC25AA3F40D98766513B342B46699EC8D716F90515148F12D9D14D` | OpenCode; DRAFT, no build/retry/submission |
| `docs/astra-unified-approval-package.md` | `3753F3A8F7F9BE64DB246D92747A268CB9D378F973C013D53DEB630867CCE247` | OpenCode; DRAFT, not submitted |
| `docs/astra-unified-security-readiness.md` | `96DAD368C0A22F15C49B3443930BF13435DD32F20F5B38E772CDEA4C40563D12` | OpenCode; readiness snapshot, not current runtime proof |
| `docs/astra-execution-decision.md` | `ADBCBBD4384B7D374162C6F01366485890CF524A3C6D99126CD258DBA3B24BD9` | OpenCode; final pre-approval snapshot, not an approval |

OpenCode source/test snapshot used for static review:

- `cloud_dispatch.py`: `89560AC39F0212AC2DBE56FA343A0921E17BCD3572CD2731888E44456C8CA68F`
- `egress_guard.py`: `9DF885F26C7D76D122D6A9BEF3E55111ABD1F8E18ADBA6BA6A9C587C5CDEE9EB`
- `dispatch_ledger.py`: `EC50E6436E257D82E7194BF9D2AEF222704DDB35CEE99B97377C17E03E0EB3CE`
- `capability_router.py`: `662D3DDE74549300B36E8F232CD42B4A6D1A4D22B758CAF0277FE9D3D7555874`
- `provider_catalog.py`: `F5D0AB4F97E921A6DF8B68AB035839015416DEED9FDD6D6620E84ECF7E6A39EA`
- `tests/agents/test_rlm_rpc.py`: `9E493512DCDADE8A96172D40598D840828A9EF5A0BA5395055AD9C71F2B0892A`
- `tests/security/test_cloud_hardening.py`: `4CB98268477CFED56CCEC44AEF16E9B3C1B2DE456D89D6F7571460FE642FEF38`
- `tests/security/test_egress_poc.py`: `D6FABA7FE2C1BA5C27684DBE65FCD666B98AF1D9D04823FE38D1160B315E60A9`
- `tests/security/test_mock_network.py`: `6F4655172DFB71513CF1D5BFD465E335193507755247956C5BD6B6FEA392271A`

## 3. Windows Application Control evidence

Read-only evidence identifies:

- Policy name: `VerifiedAndReputableDesktop`
- Policy ID: `27555.1000.240208`
- Policy GUID: `{0283ac0f-fff1-49ae-ada1-8a933130cad6}`
- Code Integrity status: `0xc0e90002`
- Code Integrity Operational logging: enabled
- Device Guard: `CodeIntegrityPolicyEnforcementStatus=2`, `UsermodeCodeIntegrityPolicyEnforcementStatus=2`
- `CiTool.exe -lp -json`: standard-user result `ACCESS_DENIED`; policy detail is not available from this context
- AppLocker EXE/DLL logging: enabled, no matching target event found
- SmartScreen debug event source: not enabled
- Policy owner / management authority: **UNKNOWN**

Observed blocked artifacts:

| Artifact | Immediate loader | Event / local evidence | Signing |
|---|---|---|---|
| Native launcher | Codex PowerShell | Code Integrity event 3077; event SHA `63E7F49F26E41D61E5AA29EA0A04FB444E1D86204E96ECE428057D19401B2A10`; flat SHA `911AA2FEC7110D956EDABF0F6A4880F59315D956FACE80BD66D7AAD92F6963AC` | Temporary executable was removed; current Authenticode state unavailable |
| `cargo.exe` | `rustup` | Code Integrity block; flat SHA `C9B44417DC8228B81923A1068A3C09E32D2793F2CCED2A816789CF433C1F0D46` | `NotSigned` |
| `maturin.exe` | `uv` | Code Integrity block; flat SHA `787779FA7F453D3444AC732689AD2BB8F1399B4D2AF1AD9E00F84BB6460F07` | `NotSigned` |

これらはポリシー拒否の証拠であり、ポリシーを無効化・回避する許可ではない。Windows App Controlの公式設計・ルール要件は [App Control for Business](https://learn.microsoft.com/en-us/windows/security/book/application-security-application-and-driver-control) および [rule types](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/select-types-of-rules-to-create) を参照する。

## 4. Error 203: remaining hypotheses

静的監査では、Unicode environment、`CREATE_UNICODE_ENVIRONMENT`、`STARTUPINFOEX`、`PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES`、profile SID、creation flagsの構成は確認対象として整合している。しかし、これだけで `CreateProcessW` の Error 203の原因は確定できない。

残る仮説は次のとおり。

1. `CREATE_SUSPENDED` と AppContainer属性・Job割り当て順序の相互作用。
2. Explicit environment blockと、Windowsが必要とする実行時環境の相互作用。host環境全体の継承を許可していないため、未検証の差分が残る。
3. Application image / current directory ACL、またはCode Integrityの評価が、環境変数エラーとして観測される可能性。
4. Security capabilitiesの属性、profile lifecycle、token生成前提の組合せ。
5. Diagnostic wrapperまたはloaderが保存したエラーと、直後の `GetLastError` の境界。

過去に失敗した `no-drive`、`no-appname`、`no-cwd` の試行は再実行していない。`CREATE_SUSPENDED`差分を含むNative検証は、正式な実行許可がないため **NOT EXECUTED**。Microsoftの仕様は [CreateProcessW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw)、[process creation flags](https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags)、[AppContainer implementation](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer)、[security capabilities attribute](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute) と照合する。

## 5. Cross-system security review

| Boundary | Static finding | Decision |
|---|---|---|
| RLM Worker | Restricted namespace、明示grant、host object非転送。Python制限はOS boundaryではない | RPC設計は保持。OS isolationは未証明 |
| HostLLMBroker | session/nonce/request identity、`llm:query`/`llm:batch` grant、RequestLedger、duplicate拒否、provider tool-call拒否、timeout/response-lossの`UNKNOWN_OUTCOME` | 安全境界は設計上維持。runtime readinessは未実行 |
| CloudDispatchAuthorizer | classification、PRIVATE local-only、capability、scanner、allowlist、endpoint束縛、digest reverify | PoC/design範囲のみ |
| EgressGuard / DispatchLedger | sealed payload、exactly-once dispatch、same-id retry拒否、partial/cancel quarantine | Production send pathへ未配線 |
| CapabilityRouter / ProviderCatalog | routing/proposalを行うがdispatch権を持たない | LLMが権限をmintしない設計 |
| Production Engine / Cloud routes | 静的検索で新しいguard/ledgerのimport・配線を確認できない | 13経路すべてNOT READY / NO-GO |
| AppContainer | Process/token/filesystem/IPC/child/network proofなし | Production統合NO-GO |

`EgressGuardedEngine`には内部engine参照があり、raw engine経路を直接利用すればguard外送信が可能なテスト上の事実もある。したがってwrapperの存在だけでProduction安全性を主張しない。Productionの13経路を全てguardへ接続し、raw pathを封鎖または別途認可する変更は、別承認なしには行わない。

LLM出力は常に提案であり、Safety Authority、MutationIntent、capability grant、ledger state、provider identityを決定しない。送信判断はtrusted host側の認可と再検証だけが行う。

## 6. Offline verification status

実行したのはファイルを読み取り `ast.parse` する静的検査だけである。

- Codex PoC / RLM関連Python 5ファイル: **AST_PARSE=PASS**
- OpenCode security/router/catalog Python 5ファイル: **AST_PARSE=PASS**
- OpenCode対象テストPython 4ファイル: **AST_PARSE=PASS**
- Production Cloud Egress wiring search: guard/ledgerのProduction importは確認できず、13経路未配線を支持
- SHA-256 inventory: **RECORDED**
- pytest、Rust build、maturin、cargo、rustc、Native launcher、AppContainer launch、live LLM、実ネットワーク: **NOT EXECUTED**

OpenCode資料には過去の `100 PASS` と `98 PASS` の記載が併存する。またRust/RLM RPCについては、ユーザー基準の12件と資料上の21件（12+9）の差がある。いずれもこのセッションで再実行しておらず、現在のPASS証拠には採用しない。

## 7. Approval requirements and compliant execution paths

### 7.1 Approval identity

- Policy owner: **UNKNOWN**
- CI execution authority: **UNKNOWN**
- Native artifact signer / distributor: **UNKNOWN**
- Rust wheel signer / distributor: **UNKNOWN**
- Executor: 未承認。Codexはポリシーを変更できない。
- Expiry: **UNKNOWN**

### 7.2 Native/AppContainer approval

必要条件は、組織管理下の許可記録、またはポリシーに適合した署名済みNative artifact / approved CI jobである。記録には、policy owner、対象絶対パスまたは署名規則、artifact SHA-256、source commit、toolchain、実行時刻、承認期限、監査ログを含める。リネーム、別パスへのコピー、未署名バイナリ、policy無効化、管理者昇格は不許可。

承認後の最小順序:

1. 承認済みNative launcherの同一性と実行許可を確認。
2. `CREATE_SUSPENDED` の差分を一つだけ実行し、`CreateProcessW`直後の`GetLastError`を保存。
3. Child process、AppContainer token/SID、integrity、capability countを確認。
4. Job containment、temporary-only filesystem、IPC negative test、child、network、cleanupを順に確認。
5. いずれかのnegative test失敗、cleanup失敗、unisolated fallback、unexpected accessで停止。

### 7.3 Rust/RLM RPC approval

必要条件は、許可済みCIまたはポリシー適合した署名済みwheel/extensionである。source commit、runner identity、toolchain digest、build command、job ID、artifact SHA-256、signature/provenance、audit log、rollbackを保存する。`cargo`、`maturin`、`rustc`の標準ユーザーによる再試行はしない。

承認後は、build/import、対象12件と拡張9件の計21件（資料上の計画値）を実行し、既存回帰へ進む。12件/21件の差は実行前に承認者が対象を確定する。

### 7.4 Cloud Egress production approval

13経路のProduction配線は独立した承認が必要である。承認条件は、全経路のguard/ledger接続、PRIVATE deny、allowlist/endpoint再検証、duplicate/no-retry、partial/cancelの`UNKNOWN_OUTCOME` quarantine、raw engine bypass封鎖、shadow denyがwire requestを発生させない証拠、flag rollbackである。Live cloud/API/networkをこの文書で許可しない。

## 8. Failure, rollback, and evidence preservation

- 認可・policy・初期化・provenance・token検証の失敗はfail-closed。
- dispatch後のtimeout、response loss、cancel、partial streamは `UNKNOWN_OUTCOME` として保全し、同一dispatch IDを再送しない。
- Native/AppContainer失敗時はprocess、Job、profile、pipe、temporary directoryをcleanupし、失敗時の直後エラー、SHA、policy eventを保存する。未隔離Workerへのfallbackは禁止。
- Rust build failure時はartifactを利用せず、既存Python経路へ安全に戻す。ただし未確定な外部送信やledger状態を再送で解決しない。
- Production Cloud Egressの段階導入でdeny/未知状態が出た場合は未配線状態へrollbackし、UNKNOWN_OUTCOME記録を削除しない。

## 9. Readiness matrix

| Area | Verified | Not Proven / current status | Blocker | Required approval |
|---|---|---|---|---|
| Windows Policy | Policy identity/eventsは一部確認 | owner、詳細ルール、許可経路 | Application Control拒否 | Policy owner |
| Native Launcher | source/hash/diagnostic静的確認 | 実行、署名、Error 203原因 | Windows policy | Policy ownerまたはapproved CI |
| Error 203 | static hypotheses整理 | root cause | Native実行不可 | 同上 |
| AppContainer Token | profile作成の過去記録のみ | child token/SID/integrity/capability | child未作成 | Native実行許可 |
| Filesystem Isolation | なし | OS-level negative proof | AppContainer未起動 | Native実行許可 |
| IPC Isolation | なし | pipe ACL positive/negative | AppContainer未起動 | Native実行許可 |
| Child Isolation | なし | Job/child containment | AppContainer未起動 | Native実行許可 |
| Network Isolation | capability設計のみ | OS-level deny proof | AppContainer未起動 | Native実行許可 |
| Rust Toolchain | block event/hashのみ | build/import/provenance | cargo/maturin/rustc blocked | Policy ownerまたはapproved CI |
| RLM RPC | source boundary/static parse | runtime 12/21 tests current result | Rust/runtime lane未実行 | approved build/CI |
| Cloud Privacy PoC | design/static parse | historical PASS not rerun; counts conflict | runtime evidence absent | test-lane approval if rerun |
| Production Cloud Egress | 13経路の未配線を確認 | end-to-end guard proof | production wiring absent | separate production approval |
| Production RLMWorker | no production change | OS isolation and File RPC absent | Phase 2D prerequisites | separate security approval |

## 10. STOP conditions

直ちに停止する条件は、policy回避・署名不明artifact・管理者昇格要求・未承認CI・Native/Rust実行ブロックの回避、unisolated fallback、token/SID不一致、filesystem/IPC bypass、unexpected network、cleanup failure、UNKNOWN_OUTCOMEの再送要求、またはProduction経路の未承認変更である。

## 11. Minimal user operation

ユーザーが実際に行う最小操作は、組織のPolicy ownerへ本資料を提出することではなく、まず **Policy ownerが発行した正式な承認記録または同等の管理下CI artifact provenance（Native launcherとRust/RLMの対象、SHA-256、期限、監査IDを含む）を取得すること** である。取得されるまで、実行・policy変更・外部提出・Production統合は行わない。

