# Astra Execution Decision (final pre-approval snapshot)

Prior docs (`astra-egress-integration-plan`, `astra-rust-build-approval-request`,
`astra-unified-approval-package`, `astra-unified-security-readiness`) hold the
evidence. This file holds only decisions. HEAD `d596e482`.

## 1. 現在の状態

- PoC 100 PASS (Fake/Mock) / 本番13経路 NOT READY / Rust BLOCKED / AppContainer NOT PROVEN
- Tracked変更ゼロ。Policy `VerifiedAndReputableDesktop` (`0283ac0f-…`)

## 2. 実証済みの安全保証

Fail-closed認可・allowlist完全一致・endpoint束縛・wire検証・no-retry・
UNKNOWN quarantine・cancel/partial語義・tier router (dispatch権なし) —
すべてFake/Mock範囲でのみ成立。

## 3. 未証明事項

本番egress保護・SDK未知形状・proxy/DNS・RLM 12件・AppContainer・
署名付き配布物の存在。

## 4. 三つの承認対象

### A. Rust Build / RLM RPC検証

Owner UNKNOWN / Executor ユーザ (管理者許可後) / Scope 当該venv+toolchain /
Artifact `openjarvis_rust` (build後にhash確定) / 順序: 許可→build→import→
21件→100件再実行 / 停止: 回帰・未知失敗。

### B. AppContainer Native実行 / OS Isolation検証

Owner UNKNOWN (Codex証拠: Error 203未解決) / Executor Codex側 /
本セッションの作業なし。判断はCodex報告に委ねる。

### C. Production Cloud Egress統合

Owner UNKNOWN / 段階順序: Direct Router→engines→Multi→callers (Broker除外)。
各段階の受入: 対応Fake/Mock全PASS + shadow DENY非送信の証明 + flag
rollback手順の確認。停止: 実網要求・bypass容認・UNKNOWN再送要求・
egress異常のいずれか。

## 5. 承認者が不明な項目

Policy所有者・CI実行権限者・配布物署名者 — すべてUNKNOWN。

## 6. 正式な承認取得方法

Policy所有者への申請 (識別情報は統合承認資料に完備)。提出は未実施。

## 7. 承認後の実行順序

A → (BはCodex) → C段階順。依存: CはAの完了を要しない (ledger分離済み) が、
回帰全体にはAが必要。

## 8. 失敗時の停止条件

§4の停止条件 + tracked変更の発生 + 未承認操作の必要性。

## 9. ユーザ判断項目 (単一確認操作に集約)

Windows セキュリティ → アプリとブラウザーのコントロール → Smart App Control
の表示 (有効/無効/管理者による管理) と、本PCの管理者 (自身/組織IT) を
それぞれ一つずつ回答すること。これにより申請先 (A/C) が確定する。
