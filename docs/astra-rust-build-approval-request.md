# Rust Build Approval Request (draft — submission requires user approval)

Status: DRAFT. No policy change, no build retry, no submission performed.

## 1. 申請目的

JARVIS Astra の必須ネイティブ拡張 `openjarvis_rust` (PyO3) を、プロジェクト
公式手順でローカルビルドするために必要な、Windows Application Control
配下での実行許可を申請する。目的は `tests/agents/test_rlm_rpc.py` 12件の
未証明解消と `make build` の成立のみ。Cloud送信・本番配線とは無関係。

## 2. 対象バイナリ

| Binary | Path | SHA-256 | Signature |
|---|---|---|---|
| maturin | `<worktree>\.venv\Scripts\maturin.exe` (26,386,944 B, 2026/09/08, uv sync由来PyPI配布物) | `787779FA7F453D3444AC732689AD2BB8F1399B4D4E2AF1AD9E00F84BB6460F07` | NotSigned |
| cargo shim | `%USERPROFILE%\.cargo\bin\cargo.exe` (rustup symlink) | NOT AVAILABLE | NOT AVAILABLE |
| rustc | rustup toolchain | NOT AVAILABLE (実行もブロック) | NOT AVAILABLE |

追加観測: `cargo --version` 自体も同ポリシー (os error 4551) で拒否。
よって maturin 単体ではなく Rust toolchain 全体が実行不可。

## 3. Windows拒否イベント

- OS: Microsoft Windows NT 10.0.26200.0
- `Microsoft-Windows-CodeIntegrity/Operational`, 2026/10/09 22:03:22:
  - Id 3077: `uv.exe` が `maturin.exe` をロード試行 — Enterprise 署名
    レベル要件未充足、Code Integrity policy 違反
    **Policy ID: `{0283ac0f-fff1-49ae-ada1-8a933130cad6}`**
  - Id 3033: 同旨 / Id 3089×2: 署名情報 / Id 3118: Smart App Control
- uv の spawn エラー文: `Failed to spawn: maturin … アプリケーション
  制御ポリシーによってこのファイルがブロックされました (os error 4551)`
- Policy Name: NOT AVAILABLE

## 4. 必要なBuild手順 (公式)

- `make build` ≡ `uv run maturin develop --manifest-path
  rust/crates/openjarvis-python/Cargo.toml` (CI `ci.yml:48-70` と同一。
  CIは `dtolnay/rust-toolchain@stable` 使用)
- Required toolchain: stable Rust (CI同等)。ローカル版本 NOT AVAILABLE
- 実行場所: OpenCode専用Worktree (`astra-opencode`, `opencode/cloud-privacy`)
  の `.venv` 内のみ。Codex Worktree・グローバル環境に影響なし

## 5. 代替となる承認済み環境

1. ポリシー管理者による本バイナリ群の正式許可 (本申請)
2. 承認済みCIでのビルド + 検証可能な署名付き配布物の受領
   (現時点で該当配布物は未確認)
3. 現状維持: Rust不要の98 PASS範囲で継続し、12件を NOT PROVEN のまま残す
   (追加承認不要)

ポリシー回避・無効化・未検証バイナリ流用は選択肢に含めない。

## 6. セキュリティ保証

- ビルド対象はリポジトリ内 `rust/` ソースのみ (`Cargo.lock` 固定)。
  依存追加・更新なし (`uv.lock` / `pyproject.toml` 無変更を事前確認済み)
- 生成物は当該 `.venv` 内に限定。署名検証は管理者の条件に従う
- Live Cloud・実API Key・外部送信は一切使用しない
- 実行テストは `tests/agents/test_rlm_rpc.py` のみ (fake/モック範囲)

## 7. 変更禁止事項

Rust Build再試行 (承認前) / ポリシー変更 / 昇格 / Production・Test
コード変更 / Codex干渉 / commit・push / AppContainer・RLMWorker変更。
本申請書の作成自体は `docs/` 新規1件のみ。

## 8. 承認後の検証手順

1. `uv run maturin develop --manifest-path rust/crates/openjarvis-python/Cargo.toml`
2. `python -c "import openjarvis_rust"` の成立
3. `pytest tests/agents/test_rlm_rpc.py` 21件 (12+9) の PASS
4. 既存98件の再実行で非回帰確認
5. `git status` でtracked変更ゼロを確認

## 9. ロールバック

ビルド失敗・回帰発生時は `.venv` を再作成 (`uv sync --frozen`、
承認済み手順) し、拡張なしの98 PASS状態へ復帰。ポリシー側の
変更は管理者の手順に従い復元する。

## 10. 未証明項目 (本申請と無関係に残る)

- Production Cloud Egress 13経路 (未配線・NOT READY)
- AppContainer OS Isolation (Codex担当・NOT PROVEN)
- 本番安全性の主張は行わない
