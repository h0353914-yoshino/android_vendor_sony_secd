# secd 1.0 可編譯重建版

> [!WARNING]
> 目前是可通過 Soong 的 ABI／服務層重建骨架，不可取代原廠服務上機。
> REA 已確認 `libdevice_security_vendor.so` 與 `libsuntory.so` 的公開函式會透過
> `IDeviceSecurity/default` 回呼服務；若直接部署目前產物，相關方法會遞迴呼叫自身。

此目錄重建 `vendor.semc.hardware.secd@1.0-service` 的 HIDL 服務層。介面 ABI 來自
原廠 `vendor.somc.hardware.security.secd@1.0.so`。19 個 HIDL 方法、初始化執行緒、
錯誤碼映射與 Soong 模組均已恢復並通過編譯。

## 編譯

將本目錄放到 LineageOS 原始碼樹內，再執行：

```bash
source build/envsetup.sh
export CCACHE_EXEC=/usr/bin/ccache
export USE_CCACHE=1
lunch lineage_poplar-cp2a-userdebug
m vendor.semc.hardware.secd@1.0-service.rebuild
```

`TARGET_RELEASE` 必須與既有 `out` 一致；本次建置樹使用 `cp2a`。若 Soong 顯示
`environment variables changed value`，應立即停止並改用目前輸出的 release。

驗證產物名稱是 `vendor.semc.hardware.secd@1.0-service.rebuild`，因此可以先與原廠
prebuilt 並存並單獨驗證。正式取代時，需停用原本的 `cc_prebuilt_binary`，再把本模組
的 `name` 與 `stem` 改回 `vendor.semc.hardware.secd@1.0-service`。

## 目前差異

原廠服務把真正的 TrustZone、Credential Manager、PIN cache 與 Suntory backend
靜態連結進執行檔。裝置上的 `libdevice_security_vendor.so` 與 `libsuntory.so` 則是
HIDL client library，不能被服務本身當成 backend。重建版目前仍連到這兩個 client
library，只供 ABI 與編譯驗證，必須先把原執行檔內的靜態 backend 移植為來源碼，
才能進行真機替換。

原廠服務會在初始化執行未匯出的 `Suntory_ConvertAllBlobs()` 與
`credmgr_init_and_open_session()`。重建版目前以原廠 helper SO 的公開 API 完成同一服務
流程；Suntory 初始化以 `Suntory_GetAllBlobStatus()` 驗證，Credential Manager 則在
`vold.post_fs_data_done=1` 後開放呼叫。這兩處仍需真機行為比對後才能宣告完全等價。

原廠 IDD protobuf 上報尚未重建；目前保留原始 log 行為，但不送出 IDD event。

## 靜態 backend 移植進度

`CredMgrBackend.cpp` 已開始直接移植 CredMgr 的資料庫建立、刪除與外部資料庫
識別判斷。依據為原廠 ARM64 執行檔的 REA/Ghidra 反編譯結果（以下為行為證據，
不是原始碼）：

- `CredMgr_DbCreate` (`0x10dc50`)，Evidence
  `ev_6bf1a23c3b0defef445bbdecc969d78997016364965e4b63612a9f07d58cbe39`
- `CredMgr_DbRemove` (`0x10e390`)，Evidence
  `ev_1aa5db6fbdecaecff171f851573a122b782f4b127c8e58b106019dba7ff1f5a9`
- `CredMgr_ExtDbIsSupported` (`0x10f084`)，Evidence
  `ev_61bf0b71eafd01f648bf807031c1dac3f274e60dbdb45c3a28a9c451d000a41c`

CredMgr 的資料庫原語目前仍未接到 credential session；session、加解密與資料查詢
仍待移植。DevSec 已加入直接 QSEECom 通道並接上五個讀取路徑：rooting status、
security config、hwconf revision、IMEI、rollback counter。對照原執行檔的程序
`devsec_tee_send` (`0x1119c8`，Evidence
`ev_998ee1f2eca2224130a5fa0a7f437c12b06046abc81bb30390846ae9d5f09830`) 與
`do_devsec_get_rooting_status` (`0x110f48`，Evidence
`ev_b2feeb9546b7ae3f3e988e8aac48ad119495325fef014c987485a15861a2e8e7`)。本次 ARM64
Soong 建置成功。DevSec 其他操作、PIN cache、Suntory、IDD backend 仍待移植；
重建版目前不可部署取代原服務。
