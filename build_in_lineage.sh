#!/usr/bin/env bash
set -o pipefail

readonly PROJECT_ROOT=/home/h/tmp/SemcCameraUI
readonly LINEAGE_ROOT=/home/h/lineageos
readonly BUILD_LOG="${PROJECT_ROOT}/.tmp/secd_rebuild_build.log"

cd "${LINEAGE_ROOT}" || exit 1
source build/envsetup.sh
export CCACHE_EXEC=/usr/bin/ccache
export USE_CCACHE=1
lunch lineage_poplar-cp2a-userdebug || exit 1
m vendor.semc.hardware.secd@1.0-service.rebuild 2>&1 | tee "${BUILD_LOG}"
exit "${PIPESTATUS[0]}"
