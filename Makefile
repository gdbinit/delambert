
PLUGIN_NAME = DeLambert

# CHANGE ME :-)
# where IDA_DIR must be the full path to ida.app (not ida64.app)
# IDA 7.5 example: /Applications/IDA Pro 7.5/ida.app/
IDA_DIR="/Applications/IDA Pro 7.6sp1/ida.app/"
# path to IDA SDK folder
IDA_SDK="/Applications/IDA Pro 7.6sp1/idasdk76"
# CHANGE ME
INSTALL_DIR="/Users/XXXXXX/.idapro/plugins"

BUILD_NUMBER_FILE=build-number.txt

CC=g++
LD=ld
LDFLAGS=-shared -m64

LIBDIR=-L$(IDA_DIR)/Contents/MacOS
SRCDIR=./
HEXRAYS_SDK=$(IDA_DIR)/Contents/MacOS/plugins/hexrays_sdk
INCLUDES=-I$(IDA_SDK)/include -I$(HEXRAYS_SDK)/include
__X64__=1

SRC=$(SRCDIR)main.cpp
	
OBJS=$(subst .cpp,.o,$(SRC))

CFLAGS=-m64 -g -fPIC -D__MAC__ -D__PLUGIN__ -std=c++14 -D_GLIBCXX_USE_CXX11_ABI=0 -Wno-logical-op-parentheses -Wno-nullability-completeness
LIBS=-lc -lpthread -ldl
EXT=dylib

CFLAGS+=
LIBS+=-lida
SUFFIX=

all: check-env $(PLUGIN_NAME)$(SUFFIX).$(EXT)

$(PLUGIN_NAME)$(SUFFIX).$(EXT): $(OBJS) $(BUILD_NUMBER_FILE)
	$(CC) $(LDFLAGS) $(BUILD_NUMBER_LDFLAGS) $(LIBDIR) -o $(PLUGIN_NAME)$(SUFFIX).$(EXT) $(OBJS) $(LIBS)

%.o: %.cpp
	$(CC) $(CFLAGS) $(BUILD_NUMBER_LDFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f $(OBJS) $(PLUGIN_NAME)$(SUFFIX).$(EXT)

install: $(PLUGIN_NAME)$(SUFFIX).$(EXT)
	cp -f $(PLUGIN_NAME)$(SUFFIX).$(EXT) $(INSTALL_DIR)

check-env:
ifndef IDA_SDK
	$(error IDA_SDK is undefined)
endif
ifndef IDA_DIR
	$(error IDA_DIR is undefined)
endif
.PHONY: check-env $(PLUGIN_NAME)$(SUFFIX).$(EXT)

include buildnumber.mak
