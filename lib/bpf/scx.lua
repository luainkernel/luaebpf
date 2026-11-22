--
-- SPDX-FileCopyrightText: (c) 2026 Ashwani Kumar Kamal <ashwanikamal.im421@gmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

---
-- Declares a sched_ext scheduler in a program file.
--
-- A scheduler is a `struct sched_ext_ops` the kernel registers as a unit: the functions it carries
-- are its callbacks, each compiled to eBPF and run by the kernel at a scheduling event, and its
-- scalar fields configure it. `scheduler` takes those as a table and hands the callbacks to the
-- compiler; the object it writes carries a `.struct_ops` section libbpf makes a struct_ops map of,
-- which `bpf_map__attach_struct_ops` registers with sched_ext. libbpf matches each member the
-- object sets to the kernel's `sched_ext_ops` by name, so the object carries only the members the
-- scheduler names, at the kernel's own byte offsets and whole size.
--
-- This first slice takes `name`, the scheduler's name, and `init`, a callback of no arguments that
-- returns `0` to let the scheduler load. The scheduler loads on a kernel built with
-- `CONFIG_SCHED_CLASS_EXT` (6.12 and later).
-- @module bpf.scx
-- @usage
-- local scx = require("bpf.scx")
--
-- return scx.scheduler{
--     name = "minimal",
--     init = function() return 0 end,
-- }

local programs  = require("luaebpf.programs")
local structops = require("luaebpf.structops")
local vmlinux   = require("bpf.vmlinux")

-- the ops struct the kernel registers; its members' offsets and whole size shift between releases,
-- so the compiler reads them from the target kernel's BTF rather than carrying one release's numbers
local STRUCT <const> = "sched_ext_ops"

local scx = {}

---
-- Declares a scheduler.
-- @function bpf.scx.scheduler
-- @tparam table opts `name`, the scheduler's name, cut to the bytes `sched_ext_ops.name` holds;
--   `init`, a callback of no arguments returning an `s32`, `0` where the scheduler is to load; and
--   `license`, the license the object declares, `Dual MIT/GPL` where it names none
-- @treturn table the declared `init` program
-- @raise `scx.scheduler takes a Lua function`, or `<file>:<line>: a scheduler callback takes no
--   argument yet`, `the kernel BTF has no struct 'sched_ext_ops'` on a kernel without sched_ext, or
--   `a scheduler is declared twice`
function scx.scheduler(opts)
	local ops = vmlinux.members(STRUCT)
	local init = assert(ops.members.init, "the kernel's sched_ext_ops has no init member")
	local field = assert(ops.members.name, "the kernel's sched_ext_ops has no name member")
	local program = programs.declare("scx.scheduler", opts.init, {section = "struct_ops/init",
		verdict = false, structops = true, license = opts.license})
	local name = (opts.name or "scx"):sub(1, field.size - 1)
	assert(structops.declare{name = name:gsub("[^%w_]", "_"), struct = STRUCT, size = ops.size, members = {
		{name = "init", offset = init.offset, program = program, proto = {params = {}}},
		{name = "name", offset = field.offset, bytes = name .. ("\0"):rep(field.size - #name)},
	}}, "a scheduler is declared twice")
	return program
end

return scx

