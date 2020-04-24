# bbootimg
LOCAL_PATH:= $(call my-dir)

bbootimg_src_file := src/bbootimg.c src/libbootimg.c

include $(CLEAR_VARS)

LOCAL_SRC_FILES:= $(bbootimg_src_file)
LOCAL_MODULE:= bbootimg
LOCAL_MODULE_TAGS := eng

LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_MODULE_PATH := $(TARGET_OUT_OPTIONAL_EXECUTABLES)
LOCAL_UNSTRIPPED_PATH := $(TARGET_OUT_EXECUTABLES_UNSTRIPPED)

LOCAL_CFLAGS := -DDEBUG_KMSG
LOCAL_STATIC_LIBRARIES := libc libcutils

include $(BUILD_EXECUTABLE)

# bbootimge_host
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= $(bbootimg_src_file)
LOCAL_MODULE := bbootimge_host
LOCAL_MODULE_STEM := bbootimg
LOCAL_MODULE_TAGS := optional

include $(BUILD_HOST_EXECUTABLE)

# bbootimg - dynamic binary for TWRP
include $(CLEAR_VARS)

LOCAL_MODULE:= bbootimg_recovery
LOCAL_MODULE_TAGS := eng
LOCAL_MODULE_CLASS := RECOVERY_EXECUTABLES
LOCAL_MODULE_PATH := $(TARGET_RECOVERY_ROOT_OUT)/sbin
LOCAL_MODULE_STEM := bbootimg

LOCAL_SRC_FILES:= src/bbootimg.c src/libbootimg.c

LOCAL_CFLAGS := -DDEBUG_KMSG
LOCAL_SHARED_LIBRARIES := libc libcutils

include $(BUILD_EXECUTABLE)

# libbootimg
include $(CLEAR_VARS)

LOCAL_SRC_FILES := src/libbootimg.c
LOCAL_MODULE := libbootimg
LOCAL_MODULE_TAGS := eng

LOCAL_CFLAGS := -DDEBUG_KMSG

include $(BUILD_STATIC_LIBRARY)
