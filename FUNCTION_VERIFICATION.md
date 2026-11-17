# secd 全函數驗證紀錄

- 原始檔 SHA-256：`8d0589be175d813b005721e88809b88de7bc8123a91a038333b0cb657d828fb0`
- 重建檔 SHA-256（2026-11-18 實機測試 build）：`f4b316dcf7c7842cb435c41acb3be91555d3ecb939e44bfb724e7767dcb51352`
- 原始服務 HIDL 入口：19 個；逐一取得 Ghidra function dossier 並與重建版對應入口比較。
- 比較維度：函數識別、反編譯偽碼、組合語言、呼叫、參照、字串／名稱、CFG。

## 結果

19 個入口全部回報 `changed`，沒有任何一個可判為結構相同；每個比較有 7 個維度變更、1 個維度相同、0 個未知。這代表重建版與原始碼的函數實作明顯不同，**不能據此宣稱行為等價或通過全函數驗證**。其中類別符號也不同（原始 `device_security`、重建 `DeviceSecurity`），所以 identity 變更本身不等於行為錯誤；偽碼、呼叫圖和 CFG 的變更仍需逐項修正及驗證。

| HIDL 方法 | 原始位址 | 重建位址 | REA 比較 | 比較 Evidence |
|---|---:|---:|---|---|
| get_startup_reason | 0x108c44 | 0x104f14 | changed | `ev_aa63552964ffe3f3fea59b3cdd05132347ad22390f7a371066060631ce4bca31` |
| tpm_protect | 0x108cf8 | 0x10500c | changed | `ev_88a91e472b413b597ad16fb7a6452da238d31c7c3911a9baa8f2c9f840a44a9d` |
| tpm_unprotect | 0x108e6c | 0x1051d0 | changed | `ev_d4250d603bd3d4c7acb6ed06852043dca12030791a5bb46ad7707ffb13df0171` |
| get_credential | 0x108fe0 | 0x105394 | changed | `ev_fc0e27a01d6f9df467c24b191e9da49ebcd25b42ac375ff97b2a4190d5c8b4e7` |
| get_rooting_status | 0x109178 | 0x105558 | changed | `ev_0b5a7a1060ee8108b081bf7be998c45463348b8084f9f2d4497298e57f81d92d` |
| get_security_config | 0x109268 | 0x10568c | changed | `ev_ce9aa62387e238d913d088946f215cd10cfedb22bf2e00cc2680603c8a77dbc6` |
| get_imei | 0x109358 | 0x1057b4 | changed | `ev_0bca256bc167dad52c3352866122dc7f803b6fb815b2d8ab665d9c8ba6bff666` |
| get_hwconf_revision | 0x1094d0 | 0x105944 | changed | `ev_35afce5f69143d06aab387cb67f25e447c333fbac0900177dcf0728c761ddc09` |
| get_debugmenu_report | 0x10963c | 0x105ae0 | changed | `ev_61d1354cd7822d0085cccb0602f5e69a1c992bcae56cb2698b34570b66a770d7` |
| get_key_prov_status | 0x10977c | 0x105c3c | changed | `ev_076e6d62ecf9aef2780ccb571a2db5b02096495cb1e764f0863e69850a8581ec` |
| pin_cache_save_pin | 0x10981c | 0x105d30 | changed | `ev_da27816b112d378d43334bc3de5439ce706a1d012612623f12dc4d34eef42c76` |
| pin_cache_read_pin | 0x1098c4 | 0x105e1c | changed | `ev_76fc131591172cf3db3b3e1784f38cb1af632214dc25c0ed41e703e022d87c41` |
| pin_cache_delete_pin | 0x109a14 | 0x105ff0 | changed | `ev_bd6a6e7685d25b9e3a5a2a2d0b0cc371348b0d21c8a817f047b979eb2fbf6c86` |
| pin_cache_set_boot_complete | 0x109a58 | 0x10603c | changed | `ev_2312b48e3bc408d356b65809123e561a4a5fe3ae7d321ee6c85c33d7a6872bc7` |
| pin_cache_get_boot_complete | 0x109a9c | 0x106148 | changed | `ev_4fedbe23328662b051cc52ac51c754d13edd03ba1d2dac9889b35bd726bda039` |
| get_rollback_counter | 0x109b34 | 0x1061c8 | changed | `ev_d975bae6391cbb553cce058d3f349edd3fe92e9d97b323b08ae6454ff665bb4d` |
| get_suntory_blob_status | 0x109c78 | 0x10635c | changed | `ev_2cf067e6769b4b61ccb931147cb195007e1682133ca81f706f0672dc312dd646` |
| get_suntory_blob | 0x109d78 | 0x1064b0 | changed | `ev_0ad0873315bedefef936271b44c0fb674d721774cfa1d6e2e27a1580920805f6` |
| remove_suntory_blob | 0x109f50 | 0x106698 | changed | `ev_74e09946a3dea788007b367eb0e210cb0db1ae1015c30548c31c69b197255a8d` |

## 驗證限制

上方 19 個入口的 REA 比較是 shipped binary 對 shipped binary 的靜態函數分析，不是 ARM64 執行期等價驗證。本文後續新增的 poplar 實機 smoke test 只覆蓋五個直接走 DevSec backend 的方法；其餘方法沒有實機輸出可供比較。重建服務仍連到會回呼 `IDeviceSecurity/default` 的 client library，因此其他路徑可能遞迴，不能據此宣稱全函數行為等價。

要完成執行期全函數對照，需先讓未覆蓋方法使用不會回呼自身的 backend，之後逐一以相同輸入比較原版與重建版的回傳值、回呼資料及副作用。現有證據已涵蓋 19 個入口的靜態結構比較、host stub 模擬，以及五個方法的 poplar 實機 smoke test；修復後五個實機輸出與原版一致；其餘 14 個入口仍未完成逐方法實機等價驗證。

## 本機模擬回歸（host stubs）

使用 `.tmp/secd_simulation/venv` 執行模擬器，直接編譯目前的 `DeviceSecurity.cpp`，並以 host Android API／backend stub 提供可控制的成功值及錯誤碼。另以 QSEE stub 編譯並執行 `DevSecBackend.cpp`。

- 19 個 HIDL 方法均有呼叫覆蓋，共 263 個 assertions 通過；expected mapping 依原版反編譯的控制流程整理。
- 覆蓋 cold／未就緒與 ready 狀態、錯誤碼與 enum 映射、startup/root/security status 邊界、credential 空／含 NUL 資料、TPM 長度 0 至容量 `0x820` 及超容量、PIN 長度 0／1／`0x200`、revision 0／1／255 bytes 及內嵌 NUL、debug report 0／1／`0x820` bytes、Suntory blob 0／1／`0x200`／`0x1000` bytes 和各階段錯誤、boot.complete 建立／重複設定／刪除。
- DevSec backend 5 個方法、45 個 QSEE 情境通過；覆蓋 4 種協定、拒絕的協定、status/config 邊界、參數錯誤、QSEE start/send/response-header 失敗及 IMEI string/raw 輸出。
- boot.complete 模擬只把測試編譯副本中的固定路徑導向 `.tmp/secd_simulation/boot_complete.fixture`；其餘 `DeviceSecurity.cpp` 邏輯為原始檔。
- 執行結果：`.tmp/secd_simulation/result.log`；暫存 fixture 與測試編譯副本於結束時移除。
- 重跑：`.tmp/secd_simulation/venv/bin/python .tmp/secd_simulation/run_simulation.py`。

這是以原版 Ghidra 反編譯所見控制流程建立 expected mapping 的模擬規格，**沒有在 host 執行原版 binary，也沒有把原版逐情境輸出自動接成 oracle**。因此結果表示重建版通過目前列出的原版規格案例，不等同所有輸入的二進位 runtime 等價。五個直接走 DevSec backend 的唯讀方法另有 poplar 實機逐項輸出比較；其餘方法目前依原版反編譯規格模擬，尚無原版／重建版的同機逐情境 runtime 比較。

## poplar 實機 smoke test（2026-11-18）

裝置：Sony G8342 / poplar，LineageOS 24（Android 17，`lineage-24.0-20261117-UNOFFICIAL-poplar`）。使用相同 HIDL client 先呼叫原版，再暫時替換重建 binary，測試五個直接走 DevSec backend 的唯讀方法。

| 方法 | 原版服務 | 初測重建服務（修正前） | 結果 |
|---|---|---|---|
| `get_rooting_status` | `2` | `-1` | 不同 |
| `get_security_config` | `1` | `1` | 相同 |
| `get_imei` | 成功，長度 15 | 成功，長度 16 | 不同 |
| `get_hwconf_revision` | 成功，`HWC_Yoshino_Com_001` | 成功，`HWC_Yoshino_Com_001` | 相同 |
| `get_rollback_counter` | 成功，256 bytes，前 8 bytes 為 `0000000000000000` | 成功，256 bytes，前 8 bytes 為 `ab01002200000000` | 不同 |

原版與重建版皆成功註冊 `IDeviceSecurity/default` 並回報 alive。測試後已還原原版 binary；裝置原檔 SHA-256 再次確認為 `8d0589be175d813b005721e88809b88de7bc8123a91a038333b0cb657d828fb0`，原版 service 為 running，`/vendor`、`/vendor/dsp` 與 `/mnt/vendor/oem_cust` 均已改回唯讀，手機上的測試副本已清除。完整操作紀錄：`/home/h/tmp/SemcCameraUI/.tmp/secd_device_test/override_smoke_restore.log`。

初次測試發現三處差異，對照原版 Ghidra 函數後修正：

- `do_devsec_get_rooting_status`（原版 `0x110f48`）：原版讀取回應 offset 40 的單一 byte；重建版先前把該處 4 bytes 當整數，鄰接欄位污染 status 判斷。現在改為讀單一 byte。
- `do_devsec_get_imei`（原版 `0x1105c4`）：原版配置 16 bytes、輸出 15 個大寫 hex nibble 並保留 NUL；重建版先前輸出 16 字元且未終止。現在按原版輸出 15 字元。
- `do_devsec_get_rollback_counter`（原版 `0x110c74`）：原版由回應 offset `0x62` 複製 256 bytes；重建版先前從 offset 4 複製。現在改為 `0x62`。
- QSEE 回應大小為 `0x183` bytes；重建版先前以 384-byte word array 接收 387 bytes。現在以精確大小的 byte array 接收，避免 3-byte 越界寫入。

修復後相同 client 的五項輸出全數與原版一致，服務成功 alive。測試完成後原版檔案 hash 已還原為 `8d0589be175d813b005721e88809b88de7bc8123a91a038333b0cb657d828fb0`，`/vendor` 已恢復唯讀，裝置測試檔清除並 adb unroot。完整紀錄：`/home/h/tmp/SemcCameraUI/.tmp/secd_device_test/repaired_override.log`。

這仍是五個 DevSec 方法的實機 smoke test，不代表 19 個 HIDL 方法全部通過。會透過 client library 回呼同一個 `default` service 的方法未在重建版上呼叫，以免觸發 README 所述遞迴路徑。

