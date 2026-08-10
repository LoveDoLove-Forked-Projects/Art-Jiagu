# Neo Art 加固 (Neo Art Jiagu)

[![Android CI](https://github.com/HSSkyBoy/Art-Jiagu/actions/workflows/android.yml/badge.svg)](https://github.com/HSSkyBoy/Art-Jiagu/actions/workflows/android.yml)
[![Release](https://img.shields.io/github/v/release/HSSkyBoy/Art-Jiagu?color=blue)](https://github.com/HSSkyBoy/Art-Jiagu/releases)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Android APK 的本機 DEX 保護工具。它會建立殼 DEX、將目標 DEX 加密後附加至殼內，並在應用程式啟動時以 native loader 在記憶體中還原與載入。

## 功能

- 全量 DEX 加密與殼 APK 重打包。
- 以 `appComponentFactory` 為主要入口；Android 9 以下或相容模式時使用 `android:name` 入口。
- 可選的簽名綁定：以 APK v2/v3 簽名憑證雜湊作為 DEX 解密材料。
- 可選的 libsu RootService 相容模式：保留 RootService 相關 DEX，不納入加密載荷。
- 可選的業務字串加密：將保守篩選後的 `const-string` 改為 native 索引解密，字串池寫入 `assets/top_strings.bin`。
- APK 重打包、zipalign 與可選的 JKS 自動簽名。

### 🛡 Native C++ 直接 Syscall 防破簽與內容完整性校驗 (Anti-Signature-Killer & Integrity Verification)
- 使用 C++ 底層 Linux 系統呼叫 `syscall(__NR_openat)` 與 `syscall(__NR_pread64)` 直接讀取物理硬碟上的 `/data/app/.../base.apk`。
- 獨立解析 APK v2 (`0x7109871a`) 与 v3 (`0xf05368c0`) 簽名區塊 (`APK Sig Block 42`)，不依賴任何 Java `PackageManager` API。
- **完全繞過 `L-JINBIN/ApkSignatureKillerEx` 等所有 Java / libc `open` Hook！**
- 將提取出的證書 SHA-256 雜湊與殼 DEX 動態綁定解密，一旦被去簽名重簽名，殼 DEX 自動解密失敗並立即崩潰閃退 (Fail-Closed)。
- 內建原生 **SHA-256 / SHA-512** 演算法，對 APK 內容進行分塊雜湊 (Chunked Hashing) 與簽名區塊內的 Digest 進行比對，**徹底防禦 Core Patch 等在不破壞簽名區塊前提下修改 APK 內容的攻擊**。

## 字串加密的範圍

字串加密預設關閉，於設定頁開啟後才生效。它只處理 DEX 中可安全判斷的字串常量，並跳過：

- 類別描述符、方法簽名、一般類別名稱與過短字串。
- `System.loadLibrary`、反射 API 與 `Resources.getIdentifier` 附近的字串。
- RootService 相容模式中被保留的整個 DEX。

此功能採保守策略：寧可不改寫不確定字串，也不改壞應用程式行為。啟用前請先以測試包驗證目標應用的啟動與核心流程。

## 建置

### 環境需求

- JDK 21
- Android SDK：Compile SDK 37、Target SDK 36、Min SDK 26
- Android Gradle Plugin 9.3.1、Gradle 9.5.1
- NDK 29.0.13846066、CMake 3.22.1


```powershell
.\gradlew testDebugUnitTest assembleDebug assembleRelease
```

- Debug APK：`app/build/outputs/apk/debug/app-debug.apk`
- Release APK：`app/build/outputs/apk/release/app-release-unsigned.apk`

## 專案結構

```text
Art-Jiagu/
├── app/src/main/
   ├── cpp/                        # Native C++ 殼與 Syscall 防護引擎
   │   ├── ApkSignatureVerifier.cpp # 直接 Syscall APK v2/v3 簽名區塊解析與內容完整性雙重校驗器
   │   ├── ArkDexLoader.cpp         # 記憶體 DEX 加密解密與 InMemoryDexClassLoader
   │   ├── ArkEnvGuard.cpp          # 環境安全檢測 (Xposed / LSPosed / Hook 檢測)
   │   └── ArkStub.cpp              # JNI 動態註冊與殼程序初始化
   ├── java/top/nkbe/art/
   │   ├── engine/                 # NPatch 可用之獨立加固引擎模組
   │   │   ├── JiaguEngine.java     # 線程安全、非阻塞式加固執行器
   │   │   ├── JiaguOptions.java    # 加固參數 (預設關閉符合按需策略)
   │   │   └── JiaguListener.java   # 日誌與進度監聽介面
   │   ├── NeoArtUi.kt             # Jetpack Compose 3 頁式與液態玻璃底欄 UI
   │   └── MainActivity.java       # 主入口與 Activity 相容層
   └── assets/                     # 預設 SO 廠商資料與偽 360 特徵
```

## 法律協議

本專案以 [Apache-2.0](LICENSE) 協議發布。
