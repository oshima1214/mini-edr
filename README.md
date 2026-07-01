# Mini EDR Scoring Prototype

Windows端末上の振る舞いをスコアリングする、学習用のミニEDRプロトタイプです。

このバージョンでは、実際の端末監視やマルウェア実行は行いません。安全な手書きのイベントJSONを読み込み、プロセス起動、親子プロセス関係、ネットワーク接続、ファイル作成、時系列のつながりから不審度を算出します。

## 目的

単一のイベントだけで判断するのではなく、複数のエンドポイントイベントの流れから不審な振る舞いを検知することを目的としています。

スコアリング時には、なぜスコアが上がったのかを検知理由として出力します。これにより、検知結果を説明しやすくし、誤検知の改善にもつなげやすい設計にしています。

## 実行方法

怪しいシナリオをスコアリングします。

```bash
python scorer.py events/suspicious_office_macro.json
```

正常な開発作業シナリオをスコアリングします。

```bash
python scorer.py events/normal_dev_workflow.json
python scorer.py events/suspicious_office_macro.json --json
```

## テスト

```bash
python -m unittest discover -s tests
```

## 実行例

```text
Risk Score: 115
Severity: HIGH
Alert: suspicious behavior detected

Reasons:
- Office process launched a script interpreter (+30)
- PowerShell used encoded command (+25)
- Script interpreter made a network connection (+20)
- Executable file was created (+20)
- Created executable was launched soon (+20)
```

## 現在できること

- JSON形式のサンプルイベントを読み込む
- イベント単体の検知ルールを評価する
- 複数イベントの時系列的なつながりを評価する
- リスクスコアと重要度を出力する
- スコアが上がった理由を表示する
- `--json` による機械処理しやすいJSONレポート出力に対応する
- 正常シナリオと怪しいシナリオを単体テストで検証する

## 現在の対象外

- 実マルウェアの実行
- 自動的なブロック、削除、隔離
- カーネルドライバ
- メモリ解析
- 常駐型のリアルタイム監視

## 構成

```text
.
├── scorer.py                         # スコアリングCLI
├── rules.json                        # 検知ルール
├── events/
│   ├── normal_dev_workflow.json       # 正常シナリオ
│   └── suspicious_office_macro.json   # 怪しいシナリオ
├── tests/
│   └── test_scorer.py                 # 単体テスト
└── docs/
    └── requirements.md                # 要件定義
```

## ロードマップ

1. 正常シナリオと怪しいシナリオを追加する
2. SQLiteにイベントとアラートを保存する
3. FastAPIでダッシュボード用APIを作成する
4. Web UIでタイムラインとアラートを表示する
5. `psutil` や `watchdog` を使って安全な実イベント収集を追加する
6. Sysmonログの取り込みに対応する

## ドキュメント

- [要件定義](docs/requirements.md)
