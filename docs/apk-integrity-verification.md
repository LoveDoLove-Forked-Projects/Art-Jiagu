# APK 完整性驗證設計

## 威脅模型

在已 Root 且 PackageManager 簽名驗證可被 Hook 的裝置上，攻擊者可能修改 APK 內容、保留原本的 APK Signing Block，並繞過安裝階段驗簽。此情境下，單純讀取 certificate SHA-256 無法證明 APK 內容未遭修改。

## 問題嚴重性評估

### 有一種常見但很多人忽略的誤區

「目前 APK 讀出的 signer certificate 沒變」只代表 APK 仍攜帶同一張憑證；它不代表 APK 的內容仍由該憑證有效簽署。在 Core Patch 這類可跳過 PMS 驗簽的 Root 環境中，攻擊者能保留原 signing block、修改 DEX 或 native library，並讓系統接受已失效的簽章。

### 風險等級：高

受影響裝置上，任何以 certificate hash 作為唯一解密材料或唯一信任根的方案都可能被繞過。風險對支付、帳號權益、反作弊、離線授權與敏感業務邏輯尤其高。

| 機制 | 在此威脅模型中的效果 |
| --- | --- |
| PackageManager 簽名 API | 不可信，可能被系統或 Java Hook 竄改。 |
| Certificate SHA-256 pinning | 不足，原 signing block 可原樣保留。 |
| META-INF/MANIFEST.MF 比對 | 只屬 v1/JAR 簽名輔助，不是 v2/v3 的完整性根。 |
| Root／Hook 偵測 | 提高成本的風險訊號，不能證明內容完整。 |
| native 直接讀 APK | 必要但不足；仍必須驗證簽章與內容 digest。 |

APK Signature Scheme v2/v3 的關鍵是對 APK 受保護內容重新計算 digest，並驗證該 digest 由 signer 的簽章保護；僅擷取 certificate 並未完成這個流程。參考 [AOSP APK Signature Scheme v2](https://source.android.com/docs/security/features/apksigning/v2)。

### 防護邊界

純本機程式無法在攻擊者可 patch native code、攔截 syscall 或控制核心的 Root 裝置上提供絕對保證。本實作的目標是讓未重新簽名的靜態竄改無法通過 loader，並明確把完全受控裝置視為高風險；高價值伺服器操作仍應驗證短時效 nonce 與 [Play Integrity](https://developer.android.com/google/play/integrity/overview) verdict。

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

## 目前實作的驗證 gate

native gate 在真實 DEX 解密前執行，且不使用 `PackageManager` 的簽名結果：

1. 由 APK 尾端定位 v2/v3 signing block。
2. 解析 signer 的 signed data、public key、signature 與 SHA-256 content digest。
3. 透過 JCA 驗證 signer 對 signed data 的 cryptographic signature。
4. 依 v2/v3 chunked digest 規格重算 APK 受保護區段的 SHA-256 digest。
5. 任一步失敗即停止 loader，不載入真實 DEX。

v2/v3 的內容保護涵蓋 ZIP entries、Central Directory、EOCD 與 signed data，因此殼 DEX、加密 payload、`lib/*.so`、Manifest 和受保護 asset 都在同一個完整性邊界內。若加固時啟用簽名綁定，loader 也會以目前 signer certificate hash 作為既有載荷的解密材料；換簽或竄改 signer 時無法取得正確載荷。
