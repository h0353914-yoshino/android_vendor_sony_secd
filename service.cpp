#include "DeviceSecurity.h"

#include <android/log.h>
#include <hidl/HidlTransportSupport.h>

using ::android::OK;
using ::android::sp;
using ::android::hardware::configureRpcThreadpool;
using ::android::hardware::joinRpcThreadpool;
using ::vendor::somc::hardware::security::secd::V1_0::implementation::
    DeviceSecurity;

int main() {
  configureRpcThreadpool(1, true);

  sp<DeviceSecurity> service = new DeviceSecurity();
  service->start_initialization_thread();

  const ::android::status_t status = service->registerAsService("default");
  if (status != OK) {
    __android_log_assert("status != android::OK", "secd@1.0-service",
                         "Could not register IDeviceSecurity");
  }

  joinRpcThreadpool();
  return 0;
}
