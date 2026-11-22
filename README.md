# luaebpf

luaebpf compiles Lua to eBPF for [Lunatik](https://github.com/luainkernel/lunatik). A program file is a
Lua file whose functions become XDP or TC programs, which the kernel runs natively on each packet a
device receives or sends; they read the packet, keep state in maps the kernel's Lua scripts share, and
hand a packet to a kernel script when Lua is what it needs.

```Lua
local xdp    = require("bpf.xdp")
local action = require("linux.xdp").action

return xdp.program(function(ctx)
	local p = ctx:packet()
	if #p < 14 then
		return action.DROP
	end
	return action.PASS
end, {default = action.PASS})
```

```Shell
sudo lunatik bpf -o /usr/local/lib/bpf/luaebpf/runt.bpf.o runt.bpf.lua
sudo lunatik run --dev=eth0 runt
```

**Experimental.** The compiler, the modules a program file's body requires and the part of Lua it
compiles may change in a minor release.

luaebpf builds and runs inside Lunatik, which mounts it at `luaebpf/`; `lunatik bpf` compiles a
program file and `lunatik run --dev` attaches it. [Compiling Lua to eBPF](doc/guide/08-luaebpf.md) is
the guide for the author of a program file, [Lua to eBPF by example](doc/guide/09-luaebpf-by-example.md)
lists what each construct compiles to, and the [design notes](doc/design/luaebpf/README.md) say how
the compiler is built. [AGENTS.md](AGENTS.md) holds the conventions for contributors.

luaebpf is dual-licensed under [MIT](LICENSE-MIT) or [GPL-2.0-only](LICENSE-GPL).
