#ifndef SECD_REBUILD_CREDMGR_BACKEND_H
#define SECD_REBUILD_CREDMGR_BACKEND_H

namespace vendor::somc::hardware::security::secd::V1_0::implementation {

// CredMgr 的本地資料庫原語；此介面不經由 IDeviceSecurity HIDL client。
int credmgr_db_create();
int credmgr_db_remove();
int credmgr_ext_db_is_supported(const char *app_id, unsigned int app_id_size,
                                const char *key_id,
                                unsigned int key_id_size, int *supported);

} // namespace vendor::somc::hardware::security::secd::V1_0::implementation

#endif
