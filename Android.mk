LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_C_INCLUDES := \
    external/sqlite/dist \
    external/libxml2/include \
    system/core/include/cutils

LOCAL_SRC_FILES:= \
	policydb.c

LOCAL_MODULE:= libpolicydb

LOCAL_SHARED_LIBRARIES := \
    liblog \
	libsqlite

LOCAL_STATIC_LIBRARIES := libxml2

include $(BUILD_SHARED_LIBRARY)
#include $(BUILD_STATIC_LIBRARY)
#LOCAL_PRELINK_MODULE := true
