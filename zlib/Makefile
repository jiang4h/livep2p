
#################################################################
#  Makefile for Security Algorith Base - secab
#  (c) 1999-2008 Ke Heng Zhong (Beijing, China)
#  Writen by ke hengzhong (kehengzhong@yahoo.com)
#################################################################

ROOT = ..
BINNAME = libz.a

adif_inc = $(ROOT)/adif
adif_src = $(ROOT)/adif

zlib_inc = $(ROOT)/zlib
zlib_src = $(ROOT)/zlib

obj = $(ROOT)/obj
dbgobj = $(ROOT)/dbgobj
dst = $(ROOT)/zlib

bin = $(dst)/$(BINNAME)
solib = $(ROOT)/bin

#################################################################
#  Customization of the implicit rules

CC = gcc -funsigned-char
#CC = gcc -funsigned-char
IFLAGS = -I/usr/include -I/usr/local/include -I$(adif_inc) -I$(zlib_inc)
DEFS = -D_DEBUG
CFLAGS = -Wall -DUNIX $(IFLAGS)
LIBS = -lnsl -lm
#LIBS = -lsocket -lnsl -lm -lxml -lz
LFLAGS = -L/usr/lib64 -L/usr/lib

#ifeq ($(MAKECMDGOALS), so)
ifneq ($(findstring so, $(MAKECMDGOALS)),)
  CFLAGS = -fPIC -DUNIX $(IFLAGS)
  ifneq ($(debug),)
	CFLAGS += \
			-g -Wall
  endif
endif

ifeq ($(MAKECMDGOALS), debug)
  CFLAGS = -g -Wall -DUNIX $(DEFS) $(IFLAGS)
  LIBS = -lnsl -lm
  bin = $(dst)/libzdbg.a
endif

#################################################################
#  Customization of the implicit rules - BRAIN DAMAGED makes (HP)

AR = ar
ARFLAGS = rv
RANLIB = ranlib
RM = /bin/rm -f
COMPILE.c = $(CC) $(CFLAGS) -c
LINK = $(CC) $(CFLAGS) $(LFLAGS) -o
SOLINK = $(CC) $(CFLAGS) $(LFLAGS) -shared -o

#################################################################
#  Modules

cnfs = $(wildcard $(zlib_inc)/*.h)
sources = $(wildcard $(zlib_src)/*.c)
objs = $(patsubst $(zlib_src)/%.c,$(obj)/%.o,$(sources))
dbgobjs = $(patsubst $(zlib_src)/%.c,$(dbgobj)/%.o,$(sources))
sobin = $(patsubst %.a,%.so,$(bin))


#################################################################
#  Standard Rules

.PHONY: all so clean debug show

all: clean $(bin)
so: clean $(sobin)
debug: clean $(bin)
clean: 
	$(RM) $(objs)
show:
	@echo $(bin)
	ls $(objs)

#################################################################
#  Additional Rules
#
#  target1 [target2 ...]:[:][dependent1 ...][;commands][#...]
#  [(tab) commands][#...]
#
#  $@ - variable, indicates the target
#  $? - all dependent files
#  $^ - all dependent files and remove the duplicate file
#  $< - the first dependent file
#  @echo - print the info to console
#
#  SOURCES = $(wildcard *.c *.cpp)
#  OBJS = $(patsubst %.c,%.o,$(patsubst %.cpp,%.o,$(SOURCES)))
#  CSRC = $(filter %.c,$(files))

$(sobin): $(objs) 
	$(SOLINK) $@ $? 
#	@cp $(sobin) $(solib)
#	$(SOLINK) $@ $? $(LIBS)

$(bin): $(objs) 
	$(AR) $(ARFLAGS) $@ $?
	$(RANLIB) $(RANLIBFLAGS) $@

$(obj)/%.o: $(zlib_src)/%.c $(cnfs)
	$(COMPILE.c) $< -o $@

