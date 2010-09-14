LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
	policydb.c

LOCAL_C_INCLUDES := \
    external/sqlite/dist

LOCAL_MODULE:= libpolicydb

LOCAL_SHARED_LIBRARIES := \
    liblog \
	libsqlite

include $(BUILD_SHARED_LIBRARY)
#include $(BUILD_STATIC_LIBRARY)
#LOCAL_PRELINK_MODULE := true
  #???
