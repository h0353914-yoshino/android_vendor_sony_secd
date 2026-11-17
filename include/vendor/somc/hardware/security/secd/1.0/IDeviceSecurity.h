#ifndef HIDL_GENERATED_VENDOR_SOMC_HARDWARE_SECURITY_SECD_V1_0_IDEVICESECURITY_H
#define HIDL_GENERATED_VENDOR_SOMC_HARDWARE_SECURITY_SECD_V1_0_IDEVICESECURITY_H

#include <android/hidl/base/1.0/IBase.h>
#include <android/hidl/manager/1.0/IServiceNotification.h>
#include <hidl/HidlSupport.h>
#include <hidl/Status.h>
#include <utils/Errors.h>

#include <cstdint>
#include <functional>
#include <string>

namespace vendor::somc::hardware::security::secd::V1_0 {

enum class secd_tpm_result : int32_t {
  OK = 0,
  GENERAL_ERROR = -1,
};

enum class credmgr_result : int32_t {
  OK = 0,
  NOT_FOUND = 1,
  INVALID_ARGUMENT = 2,
  ACCESS_DENIED = 3,
  GENERAL_ERROR = 4,
};

enum class secd_result : int32_t {
  OK = 0,
  GENERAL_ERROR = -1,
};

enum class pin_cache_result : int32_t {
  OK = 0,
  GENERAL_ERROR = 1,
  INVALID_ARGUMENT = 2,
};

enum class suntory_result : int32_t {
  OK = 0,
  GENERAL_ERROR = -1,
  NOT_FOUND = -8,
};

struct IDeviceSecurity : public ::android::hidl::base::V1_0::IBase {
  using _hidl_tag = ::android::hardware::details::i_tag;
  static const char *descriptor;

  bool isRemote() const override { return false; }

  using tpm_protect_cb = std::function<void(
      secd_tpm_result, const ::android::hardware::hidl_vec<uint8_t> &)>;
  using tpm_unprotect_cb = tpm_protect_cb;
  using get_credential_cb = std::function<void(
      credmgr_result, const ::android::hardware::hidl_vec<uint8_t> &)>;
  using get_imei_cb = std::function<void(
      secd_result, const ::android::hardware::hidl_vec<uint8_t> &)>;
  using get_hwconf_revision_cb = get_imei_cb;
  using get_debugmenu_report_cb = get_imei_cb;
  using pin_cache_read_pin_cb = std::function<void(
      pin_cache_result, const ::android::hardware::hidl_vec<uint8_t> &)>;
  using get_rollback_counter_cb = get_imei_cb;
  using get_suntory_blob_status_cb =
      std::function<void(const ::android::hardware::hidl_vec<uint8_t> &)>;
  using get_suntory_blob_cb = std::function<void(
      suntory_result, const ::android::hardware::hidl_vec<uint8_t> &)>;

  virtual ::android::hardware::Return<int32_t> get_startup_reason() = 0;
  virtual ::android::hardware::Return<void>
  tpm_protect(const ::android::hardware::hidl_vec<uint8_t> &data,
              const ::android::hardware::hidl_vec<uint8_t> &key, int32_t type,
              tpm_protect_cb callback) = 0;
  virtual ::android::hardware::Return<void>
  tpm_unprotect(const ::android::hardware::hidl_vec<uint8_t> &data,
                const ::android::hardware::hidl_vec<uint8_t> &key, int32_t type,
                tpm_unprotect_cb callback) = 0;
  virtual ::android::hardware::Return<void>
  get_credential(const ::android::hardware::hidl_vec<uint8_t> &name,
                 const ::android::hardware::hidl_vec<uint8_t> &challenge,
                 const ::android::hardware::hidl_vec<uint8_t> &context,
                 get_credential_cb callback) = 0;
  virtual ::android::hardware::Return<int32_t> get_rooting_status() = 0;
  virtual ::android::hardware::Return<int32_t> get_security_config() = 0;
  virtual ::android::hardware::Return<void> get_imei(get_imei_cb callback) = 0;
  virtual ::android::hardware::Return<void>
  get_hwconf_revision(get_hwconf_revision_cb callback) = 0;
  virtual ::android::hardware::Return<void>
  get_debugmenu_report(get_debugmenu_report_cb callback) = 0;
  virtual ::android::hardware::Return<int32_t>
  get_key_prov_status(int32_t type) = 0;
  virtual ::android::hardware::Return<pin_cache_result>
  pin_cache_save_pin(int32_t user_id,
                     const ::android::hardware::hidl_vec<uint8_t> &pin) = 0;
  virtual ::android::hardware::Return<void>
  pin_cache_read_pin(int32_t user_id, int32_t pin_id,
                     pin_cache_read_pin_cb callback) = 0;
  virtual ::android::hardware::Return<void>
  pin_cache_delete_pin(int32_t user_id, int32_t pin_id) = 0;
  virtual ::android::hardware::Return<void>
  pin_cache_set_boot_complete(int32_t complete) = 0;
  virtual ::android::hardware::Return<int32_t>
  pin_cache_get_boot_complete() = 0;
  virtual ::android::hardware::Return<void>
  get_rollback_counter(get_rollback_counter_cb callback) = 0;
  virtual ::android::hardware::Return<void>
  get_suntory_blob_status(int32_t type,
                          get_suntory_blob_status_cb callback) = 0;
  virtual ::android::hardware::Return<void>
  get_suntory_blob(int32_t type, get_suntory_blob_cb callback) = 0;
  virtual ::android::hardware::Return<int32_t>
  remove_suntory_blob(int32_t type) = 0;

  using interfaceChain_cb = std::function<void(
      const ::android::hardware::hidl_vec<::android::hardware::hidl_string> &)>;
  using interfaceDescriptor_cb =
      std::function<void(const ::android::hardware::hidl_string &)>;
  using getHashChain_cb =
      std::function<void(const ::android::hardware::hidl_vec<
                         ::android::hardware::hidl_array<uint8_t, 32>> &)>;
  using getDebugInfo_cb =
      std::function<void(const ::android::hidl::base::V1_0::DebugInfo &)>;

  ::android::hardware::Return<void>
  interfaceChain(interfaceChain_cb callback) override;
  ::android::hardware::Return<void>
  debug(const ::android::hardware::hidl_handle &fd,
        const ::android::hardware::hidl_vec<::android::hardware::hidl_string>
            &options) override;
  ::android::hardware::Return<void>
  interfaceDescriptor(interfaceDescriptor_cb callback) override;
  ::android::hardware::Return<void>
  getHashChain(getHashChain_cb callback) override;
  ::android::hardware::Return<void> setHALInstrumentation() override;
  ::android::hardware::Return<bool> linkToDeath(
      const ::android::sp<::android::hardware::hidl_death_recipient> &recipient,
      uint64_t cookie) override;
  ::android::hardware::Return<void> ping() override;
  ::android::hardware::Return<void>
  getDebugInfo(getDebugInfo_cb callback) override;
  ::android::hardware::Return<void> notifySyspropsChanged() override;
  ::android::hardware::Return<bool> unlinkToDeath(
      const ::android::sp<::android::hardware::hidl_death_recipient> &recipient)
      override;

  __attribute__((warn_unused_result)) ::android::status_t
  registerAsService(const std::string &service_name = "default");
};

} // namespace vendor::somc::hardware::security::secd::V1_0

#endif
