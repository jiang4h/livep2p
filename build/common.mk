#PATH_SRC := ..:

BASE_SRC := $(PATH_SRC)/base $(PATH_SRC)/rudp $(PATH_SRC)/tsdemux
BASE_SRC_H := -I$(PATH_SRC)/base -I$(PATH_SRC)/rudp -I$(PATH_SRC)/tsdemux
BASE_SRC_C := $(wildcard $(PATH_SRC)/base/*.c) $(wildcard $(PATH_SRC)/rudp/*.c) $(wildcard $(PATH_SRC)/tsdemux/*.c)

P2P_SRC := $(PATH_SRC)
P2P_SRC_H := -I$(PATH_SRC)
P2P_SRC_C := $(wildcard $(PATH_SRC)/*.c)

FILES := $(BASE_SRC) $(P2P_SRC)
FILES_H := -I/usr/include $(BASE_SRC_H) $(P2P_SRC_H)
FILES_C := $(BASE_SRC_C) $(P2P_SRC_C)

DEFINES := -DUNIX -funsigned-char -DHAVE_ERRNO_H -DTHREADS_POSIX -DUNIX -DOS_LINUX -DLINUX_EPOLL

LIBS := -lm -lpthread -ldl -lrt -lz -levent -levent_pthreads -rdynamic -g
