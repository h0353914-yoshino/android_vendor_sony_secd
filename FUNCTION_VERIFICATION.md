# secd 全函數驗證紀錄

- 原始檔 SHA-256：`8d0589be175d813b005721e88809b88de7bc8123a91a038333b0cb657d828fb0`
- 重建檔 SHA-256：`35bfaf648bc57f0ec30259b4317ded149fe15f71081336f94f96a3b53801f778`
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

本次是 shipped binary 對 shipped binary 的靜態函數分析／比較，不是 ARM64 執行期模擬。現有 REA 工具沒有此 Android HAL 的本機 runtime replay；依賴 Binder/HIDL、裝置檔案、Sony persist 分區與 TrustZone 的路徑，也無法在一般工作站安全地模擬其真實結果。沒有安裝或執行重建服務，亦未將結果描述為動態測試通過。

要達到真正的執行期全函數驗證，需要建立受控 Android 裝置／模擬器，提供 HIDL service、檔案系統與 QSEE/TrustZone stub，逐個入口執行輸入／輸出測試，再以原版與重建版對照。未提供這些執行環境之前，這份報告只能證明比較範圍涵蓋了 19 個 HIDL 函數，並指出目前全部存在結構差異。

## 本機模擬回歸（host stubs）

使用 `.tmp/secd_simulation/venv` 執行模擬器，直接編譯目前的 `DeviceSecurity.cpp`，並以 host Android API／backend stub 提供可控制的成功值及錯誤碼。另以 QSEE stub 編譯並執行 `DevSecBackend.cpp`。

- 19 個 HIDL 方法均有呼叫覆蓋；包含未初始化／未就緒、回傳錯誤、結果碼映射、空與多種長度輸入、資料回呼及狀態邊界，共 124 個斷言通過。
- DevSec backend 5 個方法、10 個協定情境通過。
- 執行結果：`.tmp/secd_simulation/result.log`。
- 重跑：`.tmp/secd_simulation/venv/bin/python .tmp/secd_simulation/run_simulation.py`。

此模擬驗證的是重建版程式在 stub 所提供的結果下，是否依其目前實作正確傳遞／映射輸入輸出；它**沒有執行原版 binary，也沒有用原版的逐情境輸出作為 oracle**。因此不能據此宣稱重建版成功與錯誤行為已和原版一致。實際原版對照仍需相同輸入分別驅動原版與重建版，並比較回傳值、回呼資料及可觀察副作用。

