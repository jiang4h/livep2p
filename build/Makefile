PATH_SRC := ..
include ./common.mk
all:
	/opt/android-ndk-r9d/ndk-build -B -C ./jni
	mv ./libs/armeabi/livep2p_arm* ./bin
	gcc -o ./bin/livep2p $(FILES_H) $(FILES_C) $(LIBS) $(DEFINES)

android_arm:
	/opt/android-ndk-r9d/ndk-build -BC  ./jni
	mv ./libs/armeabi/livep2p_arm* ./bin
linux:
	gcc -o ./bin/livep2p $(FILES_H) $(FILES_C) $(LIBS) $(DEFINES) -g -w 
