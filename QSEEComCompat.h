#ifndef SECD_REBUILD_QSEECOM_COMPAT_H
#define SECD_REBUILD_QSEECOM_COMPAT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct QSEECom_handle {
  unsigned char *ion_sbuffer;
};

int QSEECom_start_app(struct QSEECom_handle **handle, const char *path,
                      const char *app_name, uint32_t size);
int QSEECom_shutdown_app(struct QSEECom_handle **handle);
int QSEECom_send_cmd(struct QSEECom_handle *handle, void *send_buf,
                     uint32_t send_len, void *response_buf,
                     uint32_t response_len);
int QSEECom_set_bandwidth(struct QSEECom_handle *handle, int high);

#ifdef __cplusplus
}
#endif

#endif
