# Unified Windows Approval Package (draft — submission requires user approval)

Scope: unblock (a) Rust extension build for `test_rlm_rpc.py`,
(b) future AppContainer PoC execution review. No submission performed.
No policy change attempted.

Cross-worktree consolidation (2026-10-09, Codex worktree read-only):
Codex evidence package `tools/security_poc/windows_policy_approval_package.md`
(HASH recorded below) reports the SAME Policy GUID
`{0283ac0f-fff1-49ae-ada1-8a933130cad6}`, Policy name
`VerifiedAndReputableDesktop`, Policy ID `27555.1000.240208`,
`CodeIntegrityPolicyEnforcementStatus=2`,
`UsermodeCodeIntegrityPolicyEnforcementStatus=2`, `CiTool.exe`
ACCESS_DENIED, and an identical maturin flat hash
(`787779FA…F07`). `CreateProcessW` Error 203 remains unresolved on the
Codex side; AppContainer isolation NOT PROVEN. Events must not be mixed:
each refusal is evidenced per-binary (§1–§2 here) even though the policy
GUID is common.

## 1. cargo実行拒否

- Observed: `cargo --version` → `error: command failed: 'cargo':
  アプリケーション制御ポリシーによってこのファイルがブロックされました
  (os error 4551)`
- `cargo.exe` は rustup symlink (`→ rustup.exe`)。rustup実体自体の
  署名状態: NOT AVAILABLE (read-only metadata only; no execution)
- 影響: Rust toolchain全体が実行不可 (maturin単体の問題ではない)

## 2. maturin実行拒否

- Binary: `<worktree>\.venv\Scripts\maturin.exe`, 26,386,944 B,
  SHA-256 `787779FA7F453D3444AC732689AD2BB8F1399B4D4E2AF1AD9E00F84BB6460F07`,
  Authenticode: NotSigned, uv sync由来PyPI配布物
- Caller: `uv.exe` (`uv run maturin develop ...`)
- Events: CodeIntegrity 3077/3033/3089/3118 @2026/10/09 22:03:22,
  Policy ID `{0283ac0f-fff1-49ae-ada1-8a933130cad6}`, Policy Name NOT AVAILABLE

## 3. Native AppContainer launcher

- Codex-owned (`tools/security_poc/` in `astra-continuation` worktree).
  OpenCode側からの接触・実行・検証は一切行っていない
- 拒否証拠 (OpenCode scope): NOT AVAILABLE — 所有者(Codex)の報告に委ねる
- 本申請には含めず、将来の統合審査項目として記録のみ

## 4. 検証目的 (最小権限)

- `openjarvis_rust` (crate `openjarvis-python` → lib `openjarvis_rust`,
  cdylib) の公式手順ビルド:
  `uv run maturin develop --manifest-path
  rust/crates/openjarvis-python/Cargo.toml`
- 実行テスト: `tests/agents/test_rlm_rpc.py` のみ (fake/モック範囲、
  Live Cloud・実キー・外部送信なし)
- 書込先: 当該 `.venv` 内のみ。Codex・グローバル・ポリシーに影響なし

## 5. 正規の承認手順

1. Policy ID `0283ac0f-...` の管理者へ §1–§2 の識別情報を提出
2. 対象: `maturin.exe` (上記hash) + rustup toolchain一式の実行許可
3. 承認後は §4 の手順のみ実行し、§6 の検証で完了判定

## 6. 承認済みCI代替案

- `.github/workflows/ci.yml:48-70,140-146`: `dtolnay/rust-toolchain@stable`
  + `uv run maturin develop` (python 3.12/3.13)
- 代替として承認済みCIでのビルド+署名付き配布物受領も可 (現物未確認)

## 7. 承認後のテスト計画 / 停止条件 / 承認欄

- `import openjarvis_rust` 成立 → `test_rlm_rpc.py` 21件 → 既存100件再実行
- tracked変更ゼロを確認。回帰・未知失敗が出たら即STOPし証拠保存
- 失敗時の復帰: `.venv` 再作成 (`uv sync --frozen`) で100 PASS状態へ
- 承認者 (owner): UNKNOWN / 執行者 (executor): UNKNOWN /
  適用範囲 (scope): 当該 `.venv` + rustup toolchain の実行許可のみ /
  有効期限 (expiry): UNKNOWN (管理者が指定)
