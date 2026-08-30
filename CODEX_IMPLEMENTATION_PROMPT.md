# Codexへ貼り付ける実装依頼

以下のコードブロック全体を、**`technocore-guard` フォルダだけを開いたCodex**へ貼り付けてください。

```text
このリポジトリだけを作業範囲にしてください。親・兄弟・ホーム・Downloads・別リポジトリは読まないでください。既存の flop-technocore-starter は別場所にある秘密鍵保管庫であり、このタスクでは存在しないものとして扱ってください。

最初に AGENTS.md、UPSTREAM_BASELINE.json、docs/PRODUCT_SPEC.md、docs/THREAT_MODEL.md、docs/ARCHITECTURE.md、tasks/IMPLEMENTATION_PLAN.md、docs/DIFFERENTIATION.md を順に読んでください。AGENTS.mdの禁止事項は最優先です。

目的:
Technocore Guard v0.1.0を、完全オフライン・秘密情報非保持・fail-closedのURL副作用判定ツールとして完成度を上げる。URLを開く機能、Technocoreへの読み書き、署名、DID鍵、Faucet、ウォレット、トークン、GitHub公開は実装・実行しない。

実行手順:
1. `python scripts/preflight.py` を実行し、秘密ファイルがこのリポジトリにないことを確認する。
2. `python -m unittest discover -s tests -v`、`python scripts/security_lint.py`、`python scripts/build_release_manifest.py --check-only` を実行する。
3. 現在のコードを docs/THREAT_MODEL.md の攻撃ケースに対して敵対的にレビューする。ネットワークは使わない。外部依存をインストールしない。
4. tasks/IMPLEMENTATION_PLAN.md のうち Status が READY の項目だけを、テスト先行で実装する。BLOCKED または FUTURE は触らない。
5. 特に次を確認し、足りなければテストを追加して修正する。
   - GET形のwrite routeをreadに誤分類しない
   - POST /r/<room> と POST /kv/<ns>/<key>をwriteにする
   - userinfo、サブドメイン、末尾ドット、明示port、backslash、fragmentを拒否する
   - encoded delimiter、double encoding、encoded control、dot segmentを拒否する
   - p-系capability、本文、value、signature、nonce、raw URL、その決定論的hashを出力・台帳へ残さない
   - unknown official-origin routeを安全と推測しない
   - HEADでwrite-shaped URLを安全と推測しない
   - 台帳改竄を検出する
   - runtime packageにnetwork client importがない
6. 変更後、`PowerShell -ExecutionPolicy Bypass -File .\scripts\quality.ps1` 相当の全チェックを通す。
7. gitリポジトリであれば `git diff --check` と未コミット差分の自己レビューを行う。ただし commit、push、Issue、PR、Releaseは作らない。
8. 最後に日本語で、変更ファイル、追加した攻撃テスト、実行した検証と結果、残る曖昧さ、ネットワーク・秘密鍵・Technocore書き込み・GitHub公開を実行していないことを報告する。

絶対停止条件:
- ネットワークやパッケージ取得が必要に見えた場合は、標準ライブラリの代替を検討し、それでも必要なら停止して理由を報告する。
- .secrets、.agent、seed、mnemonic、API key、wallet、署名秘密鍵に触れる必要が出たら停止する。
- write/fetch/sign/faucet/wallet/claim機能を追加する必要があると判断したら実装せず、FUTURE案として文書に提案するだけにする。
- 公式仕様をネットワークから自動取得・自動採用しない。UPSTREAM_BASELINEの更新は人間による公式差分確認後の別作業とする。
```
