# Astra Unified Security Readiness (evidence snapshot)

HEAD `d596e482` / branch `opencode/cloud-privacy`. Tracked changes: none.
All items below are untracked additions in the OpenCode worktree only.

## 1. 実証済み機能 (executed)

- Cloud Privacy focused 65 + hardening 17 + PoC 6 + mock-network 6 +
  router 10 + catalog 4 + BoundaryGuard 21 + ollama opts 2 = **100 PASS**
- Ruff clean / compile clean / lockfile・pyproject無変更
- Cross-worktree: Policy名 `VerifiedAndReputableDesktop`・Policy ID
  `27555.1000.240208`・enforcement status 2・maturin flat hash一致を
  Codex証拠と突合 (各拒否はbinary毎に個別証拠を保持)

## 2. 未証明の安全保証

- Production 13経路のegress保護 (未配線のため保護自体が存在しない)
- SDK未知wire形状・proxy・DNS rebinding の実網検証 (設計規則のみ)
- `test_rlm_rpc` 12件 / AppContainer isolation

## 3. Windows Build blocker

- `maturin.exe` (26MB, NotSigned, sha `787779FA…F07`) spawn拒否
- `cargo` も同一ポリシーで拒否 → toolchain全体が実行不可
- CodeIntegrity 3077/3033/3089/3118, Policy `{0283ac0f-…}`, name NOT AVAILABLE
- 再試行なし。状態: BLOCKED

## 4. Rust承認手順

`docs/astra-unified-approval-package.md` に統合 (cargo+maturin証拠、
公式手順、CI代替、検証・復帰手順)。提出は未実施 (要ユーザ承認)。

## 5. AppContainer承認手順

Codex所有のためOpenCode側証拠なし。統合審査項目として記録。
`tools/security_poc/` への接触ゼロを維持。

## 6. Cloud Egress 13経路の状態

全経路 NOT READY: Broker RLM (grant+ledgerのみ) / legacy・Planner・
Tool・CLI (無認可直呼び) / Multi (prefix自動転送) / Cloud・LiteLLM・
NIM・互換 (SDK/httpx無認可) / Direct Router・routes分岐 (engine迂回)。
`verify_wire_payload` + adapter包摂の設計は完成、配線は未実施。

## 7. Production統合に必要な条件

1. Rust承認→ `test_rlm_rpc` 21件の証明
2. 13経路へのadapter配線 (別承認)
3. `make test` フルレーンのPASS
4. Shadow評価→段階強制→flag rollback手順の承認

## 8. テスト結果

100 PASS / 0 FAIL / 0 SKIP。NOT EXECUTED: Rust 12件。
過去報告値の再利用なし (今回実行分のみ計上)。

## 9. リスクと優先度

1. (高) 本番egress無保護のまま運用されること — 配線前の導入禁止で管理
2. (中) Rust未証明によるbroker回帰の盲点 — 申請が解消策
3. (低) PoCと本番の乖離 — 配線時にwire再検証が必須

## 10. 次の安全な実行ステップ

Rust承認申請書のユーザ確認・提出先決定。承認まで配線・build停止。
