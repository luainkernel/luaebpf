--
-- SPDX-FileCopyrightText: (c) 2026 Ashwani Kumar Kamal <ashwanikamal.im421@gmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

---
-- Where `bpf.scx` leaves the struct_ops object a program file's body declared.
--
-- A struct_ops object is a kernel struct of function pointers and scalars the kernel registers as a
-- unit: `sched_ext_ops` is one. The file body hands its callbacks and attributes to `bpf.scx`,
-- which records them here; `luaebpf.writer` reads them back and writes the `.struct_ops` section
-- libbpf makes a map of. A member that carries a program names the program `luaebpf.programs`
-- holds, so the writer relocates the member to that program's entry once it has an address.
-- @module luaebpf.structops

local declared = {}
local named = {}

local structops = {}

---
-- Forgets what a previous compilation declared.
-- @function luaebpf.structops.reset
function structops.reset()
	declared, named = {}, {}
end

---
-- Records one struct_ops object.
-- @function luaebpf.structops.declare
-- @tparam table ops `{name, struct, size, members}`: the name of its variable in the object, the
--   kernel struct it is an instance of, that struct's whole size in bytes, and the members it sets,
--   each `{name, offset}` with either a `program` and its `proto` `{result, params}`, or the
--   `bytes` of a scalar member
-- @treturn table|nil the same object, or `nil` when that name is already taken
function structops.declare(ops)
	if named[ops.name] ~= nil then
		return nil
	end
	named[ops.name] = ops
	table.insert(declared, ops)
	return ops
end

---
-- The struct_ops objects the file body declared, in order.
-- @function luaebpf.structops.declared
-- @treturn table
function structops.declared()
	return declared
end

return structops

