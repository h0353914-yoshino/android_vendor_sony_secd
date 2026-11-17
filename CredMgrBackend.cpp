#include "CredMgrBackend.h"

#include <sqlite3.h>

#include <cstdio>
#include <sys/stat.h>
#include <unistd.h>

namespace vendor::somc::hardware::security::secd::V1_0::implementation {
namespace {

constexpr char kDatabasePath[] = "/mnt/vendor/persist/credmgr.db";
constexpr char kCreateTableSql[] =
    "CREATE TABLE IF NOT EXISTS keytable ( dbAppId BLOB, dbUserId BLOB, "
    "dbKeyId BLOB UNIQUE, dbEncKeyType BLOB, dbData BLOB)";

int finalize_and_close(sqlite3 *db, sqlite3_stmt *statement, int result) {
  if (statement != nullptr && sqlite3_finalize(statement) != SQLITE_OK &&
      result == 0) {
    result = 1;
  }
  if (db != nullptr && sqlite3_close(db) != SQLITE_OK && result == 0) {
    result = 1;
  }
  return result;
}

} // namespace

int credmgr_db_create() {
  sqlite3 *db = nullptr;
  sqlite3_stmt *statement = nullptr;
  int result = sqlite3_open_v2(kDatabasePath, &db, SQLITE_OPEN_READWRITE |
                                                       SQLITE_OPEN_CREATE,
                               nullptr);
  if (result != SQLITE_OK) {
    return finalize_and_close(db, statement, 0x0e);
  }

  result = sqlite3_prepare_v2(db, kCreateTableSql, -1, &statement, nullptr);
  if (result == SQLITE_OK) {
    result = sqlite3_step(statement) == SQLITE_DONE ? 0 : 1;
  } else {
    result = 1;
  }
  result = finalize_and_close(db, statement, result);
  if (result == 0 && chmod(kDatabasePath, 0660) != 0) {
    result = 0x0e;
  }
  return result;
}

int credmgr_db_remove() { return remove(kDatabasePath) == 0 ? 0 : 1; }

int credmgr_ext_db_is_supported(const char *app_id, unsigned int app_id_size,
                                const char *key_id,
                                unsigned int key_id_size, int *supported) {
  if (app_id == nullptr || app_id_size == 0 || key_id == nullptr ||
      key_id_size == 0 || supported == nullptr) {
    return 3;
  }

  *supported = 0;
  constexpr char kAppId[] = "com.sonymobile.security.appid.1";
  constexpr char kKeyId1[] = "Sony-Mobile-Device-Unique-1";
  constexpr char kKeyId2[] = "Sony-Mobile-Device-Unique-2";
  if (app_id_size == sizeof(kAppId) - 1 &&
      __builtin_memcmp(app_id, kAppId, sizeof(kAppId) - 1) == 0 &&
      ((key_id_size == sizeof(kKeyId1) - 1 &&
        __builtin_memcmp(key_id, kKeyId1, sizeof(kKeyId1) - 1) == 0) ||
       (key_id_size == sizeof(kKeyId2) - 1 &&
        __builtin_memcmp(key_id, kKeyId2, sizeof(kKeyId2) - 1) == 0))) {
    *supported = 1;
  }
  return 0;
}

} // namespace vendor::somc::hardware::security::secd::V1_0::implementation
