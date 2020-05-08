LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := main
LOCAL_SRC_FILES :=  main.c
LOCAL_CFLAGS += -fPIE -pie -O2
LOCAL_LDFLAGS := -fPIE -static
LOCAL_STATIC_LIBRARIES := patch
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_MODULE := patch
LOCAL_SRC_FILES := $(PWD)/jni/patch.a
include $(PREBUILT_STATIC_LIBRARY)

