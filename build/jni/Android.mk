LOCAL_PATH := $(call my-dir)

PATH_SRC := ../..
include ../common.mk

# main
include $(CLEAR_VARS)
LOCAL_MODULE := livep2p_arm
LOCAL_SRC_FILES := $(FILES_C)
LOCAL_C_INCLUDES := $(FILES)
LOCAL_CFLAGS += $(DEFINES) -DANDROID -D_ANDROID
LOCAL_LDLIBS := -llog
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_MODULE := livep2p_arm_android5
LOCAL_SRC_FILES := $(FILES_C)
LOCAL_C_INCLUDES := $(FILES)
LOCAL_CFLAGS += $(DEFINES) -DANDROID -D_ANDROID_5
LOCAL_LDLIBS := -llog -pie -fPIE
include $(BUILD_EXECUTABLE)