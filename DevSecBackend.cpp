#include "DevSecBackend.h"

#include "QSEEComCompat.h"

#include <cstdlib>
#include <cstring>
#include <limits>

namespace vendor::somc::hardware::security::secd::V1_0::implementation {
namespace DevSecBackend {
namespace {

constexpr char kAppName[] = "tzxflattest";
constexpr uint32_t kCommand = 7;
constexpr uint32_t kRequestPayloadSize = 4;
constexpr uint32_t kResponsePayloadSize = 0x183;
constexpr uint32_t kProtocolV1 = 0x01000000;
constexpr uint32_t kProtocolV2 = 0x01100000;
constexpr uint32_t kProtocolV3 = 0x01110000;
constexpr uint32_t kProtocolLegacy = 0xdada0004;

uint32_t aligned_size(uint32_t size) {
  const uint32_t with_header = size + 8;
  return (with_header + 63U) & ~63U;
}

int send_command(uint32_t *response) {
  if (response == nullptr) {
    return 3;
  }
  const uint32_t send_size = aligned_size(kRequestPayloadSize);
  const uint32_t receive_size = aligned_size(kResponsePayloadSize);
  if (send_size > std::numeric_limits<uint32_t>::max() - receive_size) {
    return 4;
  }

  QSEECom_handle *handle = nullptr;
  int result = QSEECom_start_app(&handle, nullptr, kAppName,
                                send_size + receive_size);
  if (result != 0 || handle == nullptr || handle->ion_sbuffer == nullptr) {
    if (handle != nullptr) {
      QSEECom_shutdown_app(&handle);
    }
    return 4;
  }

  auto *request = reinterpret_cast<uint32_t *>(handle->ion_sbuffer);
  auto *reply = reinterpret_cast<uint32_t *>(handle->ion_sbuffer + send_size);
  request[0] = kCommand;
  request[1] = kRequestPayloadSize;
  request[2] = 0;
  reply[0] = 0;
  reply[1] = kResponsePayloadSize;
  memset(reply + 2, 0, kResponsePayloadSize);

  QSEECom_set_bandwidth(handle, 1);
  result = QSEECom_send_cmd(handle, request, send_size, reply, receive_size);
  QSEECom_set_bandwidth(handle, 0);
  if (result == 0 && reply[0] == 0) {
    memcpy(response, reply + 2, kResponsePayloadSize);
  } else {
    result = 4;
  }
  QSEECom_shutdown_app(&handle);
  return result == 0 ? 0 : 4;
}

bool supported_protocol(uint32_t version) {
  return version == kProtocolLegacy || version == kProtocolV1 ||
         version == kProtocolV2 || version == kProtocolV3;
}

} // namespace

int get_rooting_status(uint32_t *status) {
  if (status == nullptr) {
    return 1;
  }
  alignas(4) uint32_t response[kResponsePayloadSize / sizeof(uint32_t)] = {};
  const int result = send_command(response);
  if (result != 0) {
    return result;
  }
  if (!supported_protocol(response[0]) || response[10] >= 5) {
    return 4;
  }
  *status = response[10];
  return 0;
}

int get_security_config(int32_t *config) {
  if (config == nullptr) {
    return 1;
  }
  alignas(4) uint32_t response[kResponsePayloadSize / sizeof(uint32_t)] = {};
  const int result = send_command(response);
  if (result != 0) {
    return result;
  }
  if (!supported_protocol(response[0])) {
    return 4;
  }
  if (response[3] == 0) {
    *config = 1;
  } else if (response[3] == 0x2000) {
    *config = 0;
  } else {
    return 4;
  }
  return 0;
}

int get_hwconf_revision(char **revision) {
  if (revision == nullptr || *revision != nullptr) {
    return 1;
  }
  alignas(4) uint32_t response[kResponsePayloadSize / sizeof(uint32_t)] = {};
  const int result = send_command(response);
  if (result != 0) {
    return result;
  }
  if (!supported_protocol(response[0])) {
    return 4;
  }
  const auto *bytes = reinterpret_cast<const uint8_t *>(response);
  constexpr size_t kTextOffset = 41;
  constexpr size_t kLengthOffset = 73;
  const size_t length = bytes[kLengthOffset];
  if (length > kResponsePayloadSize - kTextOffset) {
    return 4;
  }
  auto *value = static_cast<char *>(malloc(length + 1));
  if (value == nullptr) {
    return 4;
  }
  memset(value, 0, length + 1);
  memcpy(value, bytes + kTextOffset, length);
  *revision = value;
  return 0;
}

int get_rollback_counter(uint8_t **counters, uint32_t *size) {
  if (counters == nullptr || *counters != nullptr || size == nullptr) {
    return 1;
  }
  alignas(4) uint32_t response[kResponsePayloadSize / sizeof(uint32_t)] = {};
  const int result = send_command(response);
  if (result != 0) {
    return result;
  }
  if (response[0] != kProtocolLegacy && response[0] != kProtocolV3) {
    return 4;
  }
  auto *value = static_cast<uint8_t *>(malloc(0x100));
  if (value == nullptr) {
    return 4;
  }
  memcpy(value, reinterpret_cast<const uint8_t *>(response) + 4, 0x100);
  *counters = value;
  *size = 0x100;
  return 0;
}

int get_imei(int type, char **imei, uint32_t *size) {
  if (imei == nullptr || *imei != nullptr || size == nullptr) {
    return 1;
  }
  alignas(4) uint32_t response[kResponsePayloadSize / sizeof(uint32_t)] = {};
  const int result = send_command(response);
  if (result != 0) {
    return result;
  }
  if (!supported_protocol(response[0])) {
    return 4;
  }

  const auto *raw = reinterpret_cast<const uint8_t *>(response) + 16;
  if (type == 1) {
    auto *text = static_cast<char *>(calloc(1, 16));
    if (text == nullptr) {
      return 4;
    }
    constexpr char kHex[] = "0123456789ABCDEF";
    for (size_t i = 0; i < 8; ++i) {
      text[i * 2] = kHex[raw[i] >> 4];
      text[i * 2 + 1] = kHex[raw[i] & 0x0f];
    }
    *imei = text;
    *size = 15;
    return 0;
  }
  auto *bytes = static_cast<char *>(malloc(8));
  if (bytes == nullptr) {
    return 4;
  }
  memcpy(bytes, raw, 8);
  *imei = bytes;
  *size = 8;
  return 0;
}

} // namespace DevSecBackend
} // namespace vendor::somc::hardware::security::secd::V1_0::implementation
