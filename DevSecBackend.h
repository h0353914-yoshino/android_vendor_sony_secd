#ifndef SECD_REBUILD_DEVSEC_BACKEND_H
#define SECD_REBUILD_DEVSEC_BACKEND_H

#include <cstdint>

namespace vendor::somc::hardware::security::secd::V1_0::implementation {
namespace DevSecBackend {

int get_rooting_status(uint32_t *status);
int get_security_config(int32_t *config);
int get_hwconf_revision(char **revision);
int get_imei(int type, char **imei, uint32_t *size);
int get_rollback_counter(uint8_t **counters, uint32_t *size);

} // namespace DevSecBackend
} // namespace vendor::somc::hardware::security::secd::V1_0::implementation

#endif
