#ifndef SECD_REBUILD_DEVICE_SECURITY_H
#define SECD_REBUILD_DEVICE_SECURITY_H

#include <vendor/somc/hardware/security/secd/1.0/IDeviceSecurity.h>

#include <atomic>
#include <thread>

namespace vendor::somc::hardware::security::secd::V1_0::implementation {

class DeviceSecurity final : public IDeviceSecurity {
public:
  DeviceSecurity() = default;
  ~DeviceSecurity() override;

  void start_initialization_thread();

  ::android::hardware::Return<int32_t> get_startup_reason() override;
  ::android::hardware::Return<void>
  tpm_protect(const ::android::hardware::hidl_vec<uint8_t> &data,
              const ::android::hardware::hidl_vec<uint8_t> &key, int32_t type,
              tpm_protect_cb callback) override;
  ::android::hardware::Return<void>
  tpm_unprotect(const ::android::hardware::hidl_vec<uint8_t> &data,
                const ::android::hardware::hidl_vec<uint8_t> &key, int32_t type,
                tpm_unprotect_cb callback) override;
  ::android::hardware::Return<void>
  get_credential(const ::android::hardware::hidl_vec<uint8_t> &name,
                 const ::android::hardware::hidl_vec<uint8_t> &challenge,
                 const ::android::hardware::hidl_vec<uint8_t> &context,
                 get_credential_cb callback) override;
  ::android::hardware::Return<int32_t> get_rooting_status() override;
  ::android::hardware::Return<int32_t> get_security_config() override;
  ::android::hardware::Return<void> get_imei(get_imei_cb callback) override;
  ::android::hardware::Return<void>
  get_hwconf_revision(get_hwconf_revision_cb callback) override;
  ::android::hardware::Return<void>
  get_debugmenu_report(get_debugmenu_report_cb callback) override;
  ::android::hardware::Return<int32_t>
  get_key_prov_status(int32_t type) override;
  ::android::hardware::Return<pin_cache_result> pin_cache_save_pin(
      int32_t user_id,
      const ::android::hardware::hidl_vec<uint8_t> &pin) override;
  ::android::hardware::Return<void>
  pin_cache_read_pin(int32_t user_id, int32_t pin_id,
                     pin_cache_read_pin_cb callback) override;
  ::android::hardware::Return<void>
  pin_cache_delete_pin(int32_t user_id, int32_t pin_id) override;
  ::android::hardware::Return<void>
  pin_cache_set_boot_complete(int32_t complete) override;
  ::android::hardware::Return<int32_t> pin_cache_get_boot_complete() override;
  ::android::hardware::Return<void>
  get_rollback_counter(get_rollback_counter_cb callback) override;
  ::android::hardware::Return<void>
  get_suntory_blob_status(int32_t type,
                          get_suntory_blob_status_cb callback) override;
  ::android::hardware::Return<void>
  get_suntory_blob(int32_t type, get_suntory_blob_cb callback) override;
  ::android::hardware::Return<int32_t>
  remove_suntory_blob(int32_t type) override;

private:
  void do_init_thread();
  bool wait_for_property(const char *name, const char *value);

  std::atomic_bool listeners_registered_{false};
  std::atomic_bool suntory_ready_{false};
  std::atomic_bool credmgr_ready_{false};
  std::atomic_bool stop_{false};
  std::thread init_thread_;
};

} // namespace vendor::somc::hardware::security::secd::V1_0::implementation

#endif
