#
# SPDX-FileCopyrightText: (c) 2026 Ring Zero Desenvolvimento de Software LTDA
# SPDX-License-Identifier: MIT OR GPL-2.0-only
#

# the Lunatik checkout whose lua/ and lunatik_conf.h the tables and the loader are built from,
# by default the one that mounts this tree at luaebpf/
LUNATIK ?= ..

LUA ?= lua5.5
LUA_PATH = $(shell $(LUA) -E -e 'print(package.path:match("([^;]*)/%?%.lua;"))')
LUA_CPATH = $(shell $(LUA) -E -e 'print(package.cpath:match("([^;]*)/%?%.so;"))')
LUAEBPF_INSTALL_PATH = ${LUA_PATH}/luaebpf

HOSTCC ?= cc
RM = rm -f
MKDIR = mkdir -p -m 0755
INSTALL = install -o root -g root

# the flags Lunatik's Makefile builds lunatic with
LUNATIC_CFLAGS := -std=gnu99 -O2 -Wall -D_KERNEL -DLUA_USE_LINUX -I${LUNATIK} -I${LUNATIK}/lua

# what reading and rewriting a chunk takes from lua/, printed by bytecode.c built as lunatic
# is and as the CLI's Lua is, so a chunk lunatic writes loads in the CLI's Lua
TABLES := bytecode/kernel.lua bytecode/host.lua
TABLES_SRCS := bytecode.c ${LUNATIK}/lua/lopcodes.c

# luaebpf.loader: a C module of the CLI's Lua, built against lua/ as that Lua is, over libbpf
LOADER := loader.so
LOADER_CFLAGS := -std=gnu99 -O2 -Wall -fPIC -shared -DLUA_USE_LINUX -I${LUNATIK}/lua

.PHONY: all clean install uninstall

all: ${TABLES} ${LOADER}

bytecode/kernel.lua: TABLES_CFLAGS := ${LUNATIC_CFLAGS}
bytecode/host.lua: TABLES_CFLAGS := -std=gnu99 -O2 -Wall -DLUA_USE_LINUX -I${LUNATIK}/lua
${TABLES}: ${TABLES_SRCS} $(wildcard ${LUNATIK}/lua/*.h) ${LUNATIK}/lunatik_conf.h
	${MKDIR} bytecode
	${HOSTCC} ${TABLES_CFLAGS} -o $@.bin ${TABLES_SRCS}
	./$@.bin > $@
	${RM} $@.bin

${LOADER}: loader.c $(wildcard ${LUNATIK}/lua/*.h)
	${HOSTCC} ${LOADER_CFLAGS} -o $@ $< -lbpf

clean:
	${RM} ${LOADER}
	${RM} -r bytecode

install:
	${INSTALL} -D -m 0755 ${LOADER} ${LUA_CPATH}/luaebpf/loader.so
	${RM} -r ${LUAEBPF_INSTALL_PATH}
	${MKDIR} ${LUAEBPF_INSTALL_PATH}/bytecode ${LUAEBPF_INSTALL_PATH}/emit ${LUAEBPF_INSTALL_PATH}/lib/bpf
	${INSTALL} -m 0644 *.lua ${LUAEBPF_INSTALL_PATH}
	${INSTALL} -m 0644 ${TABLES} ${LUAEBPF_INSTALL_PATH}/bytecode
	${INSTALL} -m 0644 emit/*.lua ${LUAEBPF_INSTALL_PATH}/emit
	${INSTALL} -m 0644 lib/*.lua ${LUAEBPF_INSTALL_PATH}/lib
	${INSTALL} -m 0644 lib/bpf/*.lua ${LUAEBPF_INSTALL_PATH}/lib/bpf

uninstall:
	${RM} -r ${LUAEBPF_INSTALL_PATH} ${LUA_CPATH}/luaebpf

