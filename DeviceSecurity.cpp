#include "DeviceSecurity.h"
#include "DevSecBackend.h"

#include <android/log.h>
#include <cutils/properties.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/stat.h>
#include <unistd.h>

namespace vendor::somc::hardware::security::secd::V1_0::implementation {
namespace {

constexpr const char *kLogTag = "secd@1.0-service";
constexpr const char *kBootCompletePath =
    "/mnt/vendor/persist/pc/boot.complete";
constexpr uint32_t kTpmOutputCapacity = 0x820;
constexpr uint32_t kPinOutputCapacity = 0x200;
constexpr uint32_t kSuntoryStatusSize = 0x2c;

extern "C" {
int libasb_get_startup_reason(uint32_t *reason);
int TPM_protectData(const uint8_t *data, uint32_t data_size, const uint8_t *key,
                    uint32_t key_size, int32_t type, uint8_t *output,
                    uint32_t *output_size);
int TPM_unprotectData(const uint8_t *data, uint32_t data_size,
                      const uint8_t *key, uint32_t key_size, int32_t type,
                      uint8_t *output, uint32_t *output_size);
int credmgr_get_credential(const uint8_t *name, const uint8_t *challenge,
                           uint32_t name_size, const uint8_t *context,
                           uint32_t context_size, uint8_t **output,
                           uint32_t *output_size);
int devsec_get_rooting_status(uint32_t *status);
int devsec_get_security_config(int32_t *enabled);
int devsec_get_imei(int32_t slot, char **imei, uint32_t *imei_size);
int devsec_get_hwconf_revision(char **revision);
int devsec_get_debugmenu_report(char **report);
int backend_get_key_prov_status(int32_t type,
                                int32_t *status) __asm__("get_key_prov_status");
int devsec_get_rollback_counter(uint8_t **output, uint32_t *output_size);
int pin_cache_hook_save_pin_raw(int32_t user_id, const uint8_t *pin,
                                uint32_t pin_size);
int pin_cache_hook_read_pin_raw(int32_t user_id, int32_t pin_id,
                                uint8_t *output, uint32_t *output_size,
                                uint32_t output_capacity);
void pin_cache_hook_raw_pin_delete(int32_t pin_id);
int Suntory_GetAllBlobStatus(int32_t type, uint8_t *status);
int SuntoryUtil_GetBlob(int32_t type, uint8_t *output, uint32_t *output_size);
int SuntoryUtil_RemoveBlob(int32_t type);
}

void send_idd_package(const char *routine, uint32_t message, int result) {
  if (result == 0) {
    __android_log_print(ANDROID_LOG_INFO, kLogTag, "message %d ok", message);
    return;
  }
  __android_log_print(ANDROID_LOG_ERROR, kLogTag,
                      "message %d failed, error code %d", message, result);
  __android_log_print(ANDROID_LOG_ERROR, kLogTag, "routine %s, caller %s",
                      routine, "service");
}

template <typename Result, typename Callback>
void return_buffer(Result result, uint8_t *data, uint32_t size,
                   Callback &callback) {
  ::android::hardware::hidl_vec<uint8_t> output;
  if (data != nullptr) {
    output.setToExternal(data, size);
  }
  callback(result, output);
}

int32_t normalize_vector_size(size_t size) {
  return static_cast<int32_t>(static_cast<uint32_t>(size));
}

} // namespace

DeviceSecurity::~DeviceSecurity() {
  stop_.store(true);
  if (init_thread_.joinable()) {
    init_thread_.join();
  }
}

void DeviceSecurity::start_initialization_thread() {
  listeners_registered_.store(false);
  suntory_ready_.store(false);
  credmgr_ready_.store(false);
  init_thread_ = std::thread(&DeviceSecurity::do_init_thread, this);
}

bool DeviceSecurity::wait_for_property(const char *name, const char *value) {
  char property[PROPERTY_VALUE_MAX] = {};
  while (!stop_.load()) {
    if (property_get(name, property, "") > 0 && strcmp(property, value) == 0) {
      return true;
    }
    sleep(1);
  }
  return false;
}

void DeviceSecurity::do_init_thread() {
  __android_log_print(ANDROID_LOG_INFO, kLogTag, "start init_thread");
  if (!wait_for_property("vendor.sys.listeners.registered", "true")) {
    return;
  }
  listeners_registered_.store(true);
  __android_log_print(ANDROID_LOG_INFO, kLogTag, "listeners registered");

  uint32_t rooting_status = 2;
  int result = DevSecBackend::get_rooting_status(&rooting_status);
  if (result != 0) {
    __android_log_print(ANDROID_LOG_ERROR, kLogTag,
                        "do_backend_devsec_get_rooting_status failed");
  } else if (rooting_status == 5 || rooting_status == 2) {
    __android_log_print(
        ANDROID_LOG_INFO, kLogTag,
        "the bootloader is unlocked, use limited functionality");
  } else {
    __android_log_print(ANDROID_LOG_INFO, kLogTag,
                        "the bootloader is OK, try to init suntory");
    uint8_t status[kSuntoryStatusSize] = {};
    result = Suntory_GetAllBlobStatus(0, status);
    if (result == 0) {
      suntory_ready_.store(true);
      __android_log_print(ANDROID_LOG_INFO, kLogTag, "suntory initialized");
    } else {
      for (uint32_t attempt = 1; attempt <= 4 && result != 0; ++attempt) {
        __android_log_print(ANDROID_LOG_ERROR, kLogTag,
                            "Suntory_ConvertAllBlobs failed (%d) with error %d",
                            attempt, result);
        sleep(1);
        result = Suntory_GetAllBlobStatus(0, status);
      }
      if (result == 0) {
        suntory_ready_.store(true);
        __android_log_print(ANDROID_LOG_INFO, kLogTag, "suntory initialized");
      } else {
        __android_log_print(ANDROID_LOG_ERROR, kLogTag,
                            "No more tries for Suntory_ConvertAllBlobs");
        __android_log_print(ANDROID_LOG_ERROR, kLogTag,
                            "suntory is not initialized, result %d", result);
      }
    }
  }

  __android_log_print(ANDROID_LOG_INFO, kLogTag, "wait for post_fs proprty");
  if (!wait_for_property("vold.post_fs_data_done", "1")) {
    return;
  }
  __android_log_print(ANDROID_LOG_INFO, kLogTag, "post_fs property triggered");
  credmgr_ready_.store(true);
  __android_log_print(ANDROID_LOG_INFO, kLogTag, "credmgr initialized");

  if (suntory_ready_.load()) {
    result = property_set("vendor.keyprovd.suntory.prov", "1");
    if (result == 0) {
      __android_log_print(ANDROID_LOG_INFO, kLogTag,
                          "\"vendor.keyprovd.suntory.prov\" property set");
    } else {
      __android_log_print(
          ANDROID_LOG_ERROR, kLogTag,
          "failed to set \"vendor.keyprovd.suntory.prov\" property, result %d",
          result);
    }
  }
}

::android::hardware::Return<int32_t> DeviceSecurity::get_startup_reason() {
  uint32_t reason = 0;
  const int result = libasb_get_startup_reason(&reason);
  send_idd_package("service", 400, result);
  if (result != 0) {
    __android_log_print(ANDROID_LOG_ERROR, kLogTag,
                        "libasb_get_startup_reason failed: %d", result);
  }
  return result == 0 && reason < 3 ? static_cast<int32_t>(reason) : -1;
}

::android::hardware::Return<void>
DeviceSecurity::tpm_protect(const ::android::hardware::hidl_vec<uint8_t> &data,
                            const ::android::hardware::hidl_vec<uint8_t> &key,
                            int32_t type, tpm_protect_cb callback) {
  uint8_t output[kTpmOutputCapacity] = {};
  uint32_t output_size = kTpmOutputCapacity;
  int result = -1;
  if (!listeners_registered_.load()) {
    __android_log_print(ANDROID_LOG_ERROR, kLogTag,
                        "trust zone is not ready, please wait for "
                        "'vendor.sys.listeners.registered' property");
  } else {
    result = TPM_protectData(data.data(), normalize_vector_size(data.size()),
                             key.data(), normalize_vector_size(key.size()),
                             type, output, &output_size);
  }
  send_idd_package("service", 300, result == 0 ? 0 : 1);
  if (result != 0) {
    __android_log_print(ANDROID_LOG_ERROR, kLogTag,
                        "TPM_protectData failed: %d", result);
  }
  return_buffer(
      result == 0 ? secd_tpm_result::OK : secd_tpm_result::GENERAL_ERROR,
      result == 0 ? output : nullptr, result == 0 ? output_size : 0, callback);
  return {};
}

::android::hardware::Return<void> DeviceSecurity::tpm_unprotect(
    const ::android::hardware::hidl_vec<uint8_t> &data,
    const ::android::hardware::hidl_vec<uint8_t> &key, int32_t type,
    tpm_unprotect_cb callback) {
  uint8_t output[kTpmOutputCapacity] = {};
  uint32_t output_size = kTpmOutputCapacity;
  int result = -1;
  if (!listeners_registered_.load()) {
    __android_log_print(ANDROID_LOG_ERROR, kLogTag,
                        "trust zone is not ready, please wait for "
                        "'vendor.sys.listeners.registered' property");
  } else {
    result = TPM_unprotectData(data.data(), normalize_vector_size(data.size()),
                               key.data(), normalize_vector_size(key.size()),
                               type, output, &output_size);
  }
  send_idd_package("service", 301, result == 0 ? 0 : 1);
  if (result != 0) {
    __android_log_print(ANDROID_LOG_ERROR, kLogTag,
                        "TPM_unprotectData failed: %d", result);
  }
  return_buffer(
      result == 0 ? secd_tpm_result::OK : secd_tpm_result::GENERAL_ERROR,
      result == 0 ? output : nullptr, result == 0 ? output_size : 0, callback);
  return {};
}

::android::hardware::Return<void> DeviceSecurity::get_credential(
    const ::android::hardware::hidl_vec<uint8_t> &name,
    const ::android::hardware::hidl_vec<uint8_t> &challenge,
    const ::android::hardware::hidl_vec<uint8_t> &context,
    get_credential_cb callback) {
  int result = 4;
  uint8_t *output = nullptr;
  uint32_t output_size = 0;
  if (!credmgr_ready_.load()) {
    __android_log_print(ANDROID_LOG_ERROR, kLogTag,
                        "credmgr is not ready, please wait for "
                        "'vendor.keyprovd.suntory.prov' property");
  } else {
    result = credmgr_get_credential(
        name.data(), challenge.data(), normalize_vector_size(name.size()),
        context.data(), normalize_vector_size(context.size()), &output,
        &output_size);
  }
  send_idd_package("credmgr", 202, result);
  credmgr_result mapped = credmgr_result::GENERAL_ERROR;
  if (result >= 0 && result <= 4) {
    mapped = static_cast<credmgr_result>(result);
  }
  if (result == 4) {
    __android_log_print(ANDROID_LOG_ERROR, kLogTag,
                        "credmgr_get_credential failed: %d", result);
  }
  return_buffer(mapped, result == 0 ? output : nullptr,
                result == 0 ? output_size : 0, callback);
  free(output);
  return {};
}

::android::hardware::Return<int32_t> DeviceSecurity::get_rooting_status() {
  uint32_t status = 0;
  int result = 4;
  if (!listeners_registered_.load()) {
    __android_log_print(ANDROID_LOG_ERROR, kLogTag,
                        "trust zone is not ready, please wait for "
                        "'vendor.sys.listeners.registered' property");
  } else {
    result = DevSecBackend::get_rooting_status(&status);
  }
  send_idd_package("devsec", 10, result);
  if (result != 0) {
    __android_log_print(ANDROID_LOG_ERROR, kLogTag,
                        "devsec_get_rooting_status failed: %d", result);
  }
  return result == 0 && status < 6 ? static_cast<int32_t>(status) : -1;
}

::android::hardware::Return<int32_t> DeviceSecurity::get_security_config() {
  int32_t enabled = 0;
  int result = 4;
  if (!listeners_registered_.load()) {
    __android_log_print(ANDROID_LOG_ERROR, kLogTag,
                        "trust zone is not ready, please wait for "
                        "'vendor.sys.listeners.registered' property");
  } else {
    result = DevSecBackend::get_security_config(&enabled);
  }
  send_idd_package("devsec", 14, result);
  if (result != 0) {
    __android_log_print(ANDROID_LOG_ERROR, kLogTag,
                        "devsec_get_security_config failed: %d", result);
    return -1;
  }
  return enabled != 0 ? 1 : 0;
}

::android::hardware::Return<void>
DeviceSecurity::get_imei(get_imei_cb callback) {
  char *imei = nullptr;
  uint32_t imei_size = 0;
  int result = 4;
  if (!listeners_registered_.load()) {
    __android_log_print(ANDROID_LOG_ERROR, kLogTag,
                        "trust zone is not ready, please wait for "
                        "'vendor.sys.listeners.registered' property");
  } else {
    result = DevSecBackend::get_imei(1, &imei, &imei_size);
  }
  send_idd_package("devsec", 8, result);
  if (result != 0) {
    __android_log_print(ANDROID_LOG_ERROR, kLogTag,
                        "devsec_get_imei failed: %d", result);
  }
  const uint32_t size = result == 0 ? strlen(imei) : 0;
  return_buffer(result == 0 ? secd_result::OK : secd_result::GENERAL_ERROR,
                result == 0 ? reinterpret_cast<uint8_t *>(imei) : nullptr, size,
                callback);
  free(imei);
  return {};
}

::android::hardware::Return<void>
DeviceSecurity::get_hwconf_revision(get_hwconf_revision_cb callback) {
  char *revision = nullptr;
  const int result =
      listeners_registered_.load()
          ? DevSecBackend::get_hwconf_revision(&revision)
          : 4;
  if (!listeners_registered_.load()) {
    __android_log_print(ANDROID_LOG_ERROR, kLogTag,
                        "trust zone is not ready, please wait for "
                        "'vendor.sys.listeners.registered' property");
  }
  send_idd_package("devsec", 6, result);
  if (result != 0) {
    __android_log_print(ANDROID_LOG_ERROR, kLogTag,
                        "devsec_get_hwconf_revision failed: %d", result);
  }
  return_buffer(result == 0 ? secd_result::OK : secd_result::GENERAL_ERROR,
                result == 0 ? reinterpret_cast<uint8_t *>(revision) : nullptr,
                result == 0 ? strlen(revision) : 0, callback);
  free(revision);
  return {};
}

::android::hardware::Return<void>
DeviceSecurity::get_debugmenu_report(get_debugmenu_report_cb callback) {
  char *report = nullptr;
  const int result = devsec_get_debugmenu_report(&report);
  send_idd_package("devsec", 34, result);
  if (result != 0) {
    __android_log_print(ANDROID_LOG_ERROR, kLogTag,
                        "devsec_get_debugmenu_report failed: %d", result);
  }
  return_buffer(result == 0 ? secd_result::OK : secd_result::GENERAL_ERROR,
                result == 0 ? reinterpret_cast<uint8_t *>(report) : nullptr,
                result == 0 ? strlen(report) : 0, callback);
  free(report);
  return {};
}

::android::hardware::Return<int32_t>
DeviceSecurity::get_key_prov_status(int32_t type) {
  int32_t status = 1;
  const int result = backend_get_key_prov_status(type, &status);
  send_idd_package("devsec", 36, result);
  return result == 0 ? (status == 0 ? 1 : 0) : -1;
}

::android::hardware::Return<pin_cache_result>
DeviceSecurity::pin_cache_save_pin(
    int32_t user_id, const ::android::hardware::hidl_vec<uint8_t> &pin) {
  int result = 1;
  if (!listeners_registered_.load()) {
    __android_log_print(ANDROID_LOG_ERROR, kLogTag,
                        "trust zone is not ready, please wait for "
                        "'vendor.sys.listeners.registered' property");
  } else {
    result = pin_cache_hook_save_pin_raw(user_id, pin.data(),
                                         normalize_vector_size(pin.size()));
  }
  send_idd_package("service", 402, result);
  return result == 0   ? pin_cache_result::OK
         : result == 2 ? pin_cache_result::INVALID_ARGUMENT
                       : pin_cache_result::GENERAL_ERROR;
}

::android::hardware::Return<void>
DeviceSecurity::pin_cache_read_pin(int32_t user_id, int32_t pin_id,
                                   pin_cache_read_pin_cb callback) {
  uint8_t output[kPinOutputCapacity] = {};
  uint32_t output_size = kPinOutputCapacity;
  int result = 1;
  if (!listeners_registered_.load()) {
    __android_log_print(ANDROID_LOG_ERROR, kLogTag,
                        "trust zone is not ready, please wait for "
                        "'vendor.sys.listeners.registered' property");
  } else {
    result = pin_cache_hook_read_pin_raw(user_id, 0, output, &output_size,
                                         kPinOutputCapacity);
  }
  send_idd_package("service", 403, result);
  if (result != 0) {
    __android_log_print(ANDROID_LOG_ERROR, kLogTag,
                        "pin_cache_hook_read_pin_raw failed: %d", result);
  }
  return_buffer(
      result == 0 ? pin_cache_result::OK : pin_cache_result::GENERAL_ERROR,
      result == 0 ? output : nullptr, result == 0 ? output_size : 0, callback);
  return {};
}

::android::hardware::Return<void>
DeviceSecurity::pin_cache_delete_pin(int32_t user_id, int32_t pin_id) {
  pin_cache_hook_raw_pin_delete(pin_id);
  send_idd_package("service", 404, 0);
  return {};
}

::android::hardware::Return<void>
DeviceSecurity::pin_cache_set_boot_complete(int32_t complete) {
  struct stat info{};
  const int state = stat(kBootCompletePath, &info);
  if (complete == 0) {
    if (state != -1) {
      unlink(kBootCompletePath);
    }
  } else if (state == -1) {
    FILE *file = fopen(kBootCompletePath, "w");
    if (file == nullptr) {
      __android_log_print(ANDROID_LOG_ERROR, "libasb:libpin-cache",
                          "failed to create boot.complete file");
    } else {
      fflush(file);
      fsync(fileno(file));
      fclose(file);
    }
  }
  send_idd_package("service", 405, 0);
  return {};
}

::android::hardware::Return<int32_t>
DeviceSecurity::pin_cache_get_boot_complete() {
  struct stat info{};
  return stat(kBootCompletePath, &info) != -1 ? 1 : 0;
}

::android::hardware::Return<void>
DeviceSecurity::get_rollback_counter(get_rollback_counter_cb callback) {
  uint8_t *output = nullptr;
  uint32_t output_size = 0;
  int result = 4;
  if (!listeners_registered_.load()) {
    __android_log_print(ANDROID_LOG_ERROR, kLogTag,
                        "trust zone is not ready, please wait for "
                        "'vendor.sys.listeners.registered' property");
  } else {
    result = DevSecBackend::get_rollback_counter(&output, &output_size);
  }
  send_idd_package("devsec", 38, result);
  if (result != 0) {
    __android_log_print(ANDROID_LOG_ERROR, kLogTag,
                        "devsec_get_rollback_counter failed: %d", result);
  }
  return_buffer(result == 0 ? secd_result::OK : secd_result::GENERAL_ERROR,
                result == 0 ? output : nullptr, result == 0 ? output_size : 0,
                callback);
  free(output);
  return {};
}

::android::hardware::Return<void>
DeviceSecurity::get_suntory_blob_status(int32_t type,
                                        get_suntory_blob_status_cb callback) {
  uint8_t status[kSuntoryStatusSize] = {};
  int result = -1;
  if (!suntory_ready_.load()) {
    __android_log_print(ANDROID_LOG_ERROR, kLogTag,
                        "suntory is not ready, please wait for "
                        "'vendor.keyprovd.suntory.prov' property");
  } else {
    result = Suntory_GetAllBlobStatus(type, status);
  }
  send_idd_package("suntory", 500, result);
  ::android::hardware::hidl_vec<uint8_t> output;
  if (result == 0) {
    output.setToExternal(status, kSuntoryStatusSize);
  }
  callback(output);
  return {};
}

::android::hardware::Return<void>
DeviceSecurity::get_suntory_blob(int32_t type, get_suntory_blob_cb callback) {
  uint32_t output_size = 0;
  int result = -1;
  uint8_t *output = nullptr;
  if (!suntory_ready_.load()) {
    __android_log_print(ANDROID_LOG_ERROR, kLogTag,
                        "suntory is not ready, please wait for "
                        "'vendor.keyprovd.suntory.prov' property");
  } else {
    result = SuntoryUtil_GetBlob(type, nullptr, &output_size);
    if (result == 0) {
      output = static_cast<uint8_t *>(malloc(output_size));
      result = SuntoryUtil_GetBlob(type, output, &output_size);
    }
  }
  send_idd_package("suntory", 501, result);
  suntory_result mapped = suntory_result::GENERAL_ERROR;
  if (result == 0) {
    mapped = suntory_result::OK;
  } else if (result == -8) {
    mapped = suntory_result::NOT_FOUND;
    __android_log_print(ANDROID_LOG_ERROR, kLogTag,
                        "SuntoryUtil_GetBlob failed: %d, not found", result);
  } else {
    __android_log_print(ANDROID_LOG_ERROR, kLogTag,
                        "SuntoryUtil_GetBlob failed: %d, general error",
                        result);
  }
  return_buffer(mapped, result == 0 ? output : nullptr,
                result == 0 ? output_size : 0, callback);
  free(output);
  return {};
}

::android::hardware::Return<int32_t>
DeviceSecurity::remove_suntory_blob(int32_t type) {
  int result = -1;
  if (!suntory_ready_.load()) {
    __android_log_print(ANDROID_LOG_ERROR, kLogTag,
                        "suntory is not ready, please wait for "
                        "'vendor.keyprovd.suntory.prov' property");
  } else {
    result = SuntoryUtil_RemoveBlob(type);
  }
  send_idd_package("suntory", 502, result);
  return result == 0 ? 0 : result == -3 ? -3 : -1;
}

} // namespace vendor::somc::hardware::security::secd::V1_0::implementation
