# APK 完整性驗證設計

## 威脅模型

在已 Root 且 PackageManager 簽名驗證可被 Hook 的裝置上，攻擊者可能修改 APK 內容、保留原本的 APK Signing Block，並繞過安裝階段驗簽。此情境下，單純讀取 certificate SHA-256 無法證明 APK 內容未遭修改。

## 安全目標

1. native 層驗證 APK v2/v3 簽名的簽章與內容 digest，而非只提取憑證。
2. 驗證關鍵載荷（殼 DEX、加密 DEX payload、native library、Manifest 與字串池）的完整性清單。
3. 讓 loader 在完整性驗證失敗時不載入真實 DEX。
4. 將 Root／Hook 偵測視為風險訊號，不作為完整性驗證的替代品。

## 非目標

本機程式無法在攻擊者完全控制 Root 裝置、可 patch native code 或攔截 syscalls 時提供絕對保證。高價值操作仍須搭配伺服器端 nonce 與 Play Integrity verdict。

## 實作分層

| 層級 | 責任 |
| --- | --- |
| APK v2/v3 verifier | 驗證 signer、signed data 與 APK content digest。 |
| Integrity manifest | 加固時建立關鍵輸入的 hash 清單；執行時 native 重新計算。 |
| Loader gate | 完整性失敗時停止解密／載入真實 DEX。 |
| Server policy | 對敏感請求驗證 app 與 device integrity verdict。 |
