# Working on luaebpf

Conventions for contributors, and for AI coding assistants working on this repository. What luaebpf
shares with Lunatik is the harness mounted at `harness/` (luainkernel/harness): `harness/AGENTS.md`,
which binds here as this file does, its rules, skills and agents, and the scripts under
`harness/tools/`, where a path that file names under `tools/`, `.agents/` or `.claude/` lies. This file
holds what speaks of luaebpf alone, under the section names that file uses. An issue or a pull request
named by its number alone, #N, is this repository's; one of Lunatik's is `luainkernel/lunatik#N`, as the
history taken from Lunatik names them.

luaebpf compiles Lua to eBPF for Lunatik: a program file, Lua whose functions become eBPF programs, is
compiled on the host into a BPF object that Lunatik's `lunatik run --dev` attaches to a device and that
calls the kernel Lua scripts Lunatik runs.

## Layout

| Path | What lives there |
|------|------------------|
| `init.lua` and the modules beside it | the compiler, `luaebpf`, a package of the CLI's Lua: `proto.lua` and `undump.lua` read the chunk `lunatic` writes, `emit/` lowers it, a module per construct, `btf.lua`, `elf.lua` and `writer.lua` write the object, `errors.lua` reads the errors a running program counted |
| `lib/` | the modules a program file's body requires to declare what the object carries, `bpf.xdp`, `bpf.tc`, `bpf.map` and `bpf.vmlinux`; one named as a kernel module of Lunatik is that module's compile-time twin |
| `loader.c` | `luaebpf.loader`, the C module over libbpf that loads, attaches and pins an object |
| `bytecode.c` | the program `make` runs, as `lunatic` is built, to print the tables of the kernel's Lua bytecode the compiler reads |
| `doc/guide/` | the guide's two pages of the compiler, which Lunatik's site builds |
| `doc/design/luaebpf/` | the compiler's design notes |
| `harness/` | the harness luaebpf shares with Lunatik (luainkernel/harness), mounted as a submodule |
| `.agents/rules/` | luaebpf's own rules for a kind of file |
| `.agents/harness.conf` | what the shared scripts of `harness/` read of this tree |
| `.claude/` | Claude Code's wiring of the guards, the checks, the skills, the agents and the rules, with no logic of its own |
| `.github/` | the CI workflows |

## Build, install, test

    make LUNATIK=<a Lunatik checkout>    # .. by default
    sudo make install
    sudo make uninstall
    make clean

`make` builds the loader against libbpf and the bytecode tables, both over the `lua/` of the Lunatik
checkout `LUNATIK` names, `..` by default, which is Lunatik's root where it mounts luaebpf at
`luaebpf/` (luainkernel/lunatik#2598); the kernel's table takes that checkout's `lunatik_conf.h` too,
and the flags Lunatik's Makefile builds `lunatic` with. `sudo make install` puts the compiler under
the host's `LUA_PATH` as `luaebpf/` and the loader under `LUA_CPATH` as `luaebpf/loader.so`.

The program files of its tests live in Lunatik's `tests/luaebpf/`, and its examples in Lunatik's
`examples/`. A change is built, installed and run in a Lunatik checkout, with the mount at the
change's commit, as Lunatik's AGENTS.md says of a build and of its suite; the program files Lunatik's
suite compiles are the compiler's tests.

The compiler reads what Lunatik installs: `lunatic` on the `PATH`, `lunatik.class` and
`lunatik.config` under the host's `LUA_PATH`, and under `/lib/modules/lua` the kernel scripts a
program file's body requires and the `linux.*` tables, the ones those scripts read too. A constant
the compiler needs enters Lunatik's `autogen/specs.lua` through a pull request of Lunatik.

### Checks

luaebpf has no checks of its own: the shared ones run from `harness/tools/checks/`, reading this tree
through `.agents/harness.conf`. Lunatik's own read Lunatik's tree, where a change of luaebpf is a move
of the mount and none of its files.

## Releases

A release is a tag of this repository, `v0.1` the first, and names the Lunatik release or commit it
needs. Lunatik carries it at the commit its mount pins, gathered per Lunatik release.
