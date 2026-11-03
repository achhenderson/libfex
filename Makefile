# SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only
#
# Plain Makefile for libfex - no cmake required. Builds the static
# library plus the passthrough example.

CXX        ?= g++
CXXSTD     ?= -std=c++23
WARN       ?= -Wall -Wextra -Wpedantic -Wshadow -Wno-unused-parameter
OPT        ?= -O2 -g -fPIC
CXXFLAGS   ?= $(CXXSTD) $(WARN) $(OPT) -Iinclude
LDFLAGS    ?= -pthread -luring

PREFIX     ?= /usr/local
BUILD      ?= build
LIB        := $(BUILD)/libfex.a
SO         := $(BUILD)/libfex.so.0.1.0
BIN        := $(BUILD)/fex-passthrough
TEST       := $(BUILD)/fex-notify-test
MEMFS      := $(BUILD)/fex-memfs

LIB_SRCS   := src/session.cpp src/handlers.cpp src/mount.cpp \
              src/uring_worker.cpp src/notifier.cpp src/reply.cpp
LIB_OBJS   := $(LIB_SRCS:%.cpp=$(BUILD)/%.o)

.PHONY: all clean install
all: $(LIB) $(SO) $(BIN) $(TEST) $(MEMFS)

$(BUILD)/%.o: %.cpp
	@mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) -MMD -MP -c $< -o $@

$(LIB): $(LIB_OBJS)
	@mkdir -p $(@D)
	$(AR) rcs $@ $^

$(SO): $(LIB_OBJS)
	@mkdir -p $(@D)
	$(CXX) -shared -Wl,-soname,libfex.so.0 $^ -o $@ $(LDFLAGS)
	ln -sf libfex.so.0.1.0 $(BUILD)/libfex.so.0
	ln -sf libfex.so.0     $(BUILD)/libfex.so

$(BIN): examples/passthrough.cpp examples/daemonize.hpp $(LIB)
	$(CXX) $(CXXFLAGS) $< $(LIB) -o $@ $(LDFLAGS)

$(TEST): examples/notify_test.cpp $(LIB)
	$(CXX) $(CXXFLAGS) $< $(LIB) -o $@ $(LDFLAGS)

$(MEMFS): examples/memfs.cpp examples/daemonize.hpp $(LIB)
	$(CXX) $(CXXFLAGS) $< $(LIB) -o $@ $(LDFLAGS)

-include $(LIB_OBJS:.o=.d)

clean:
	rm -rf $(BUILD)

install: all
	install -d $(DESTDIR)$(PREFIX)/lib $(DESTDIR)$(PREFIX)/bin \
	           $(DESTDIR)$(PREFIX)/include/fex
	install -m 0755 $(SO) $(DESTDIR)$(PREFIX)/lib/
	ln -sf libfex.so.0.1.0 $(DESTDIR)$(PREFIX)/lib/libfex.so.0
	ln -sf libfex.so.0     $(DESTDIR)$(PREFIX)/lib/libfex.so
	install -m 0644 $(LIB) $(DESTDIR)$(PREFIX)/lib/
	install -m 0644 include/fex/*.h include/fex/*.hpp \
	    $(DESTDIR)$(PREFIX)/include/fex/
	install -m 0755 $(BIN) $(MEMFS) $(DESTDIR)$(PREFIX)/bin/
