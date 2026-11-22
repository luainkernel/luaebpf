--
-- SPDX-FileCopyrightText: (c) 2026 Ring Zero Desenvolvimento de Software LTDA
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

---
-- Writes the BPF ELF object `luaebpf.compile` returns, from the programs a program file's body
-- declared.
--
-- Each program is lowered by `luaebpf.emit` and laid out with `luaebpf.elf` and `luaebpf.btf`, in
-- the byte order `luaebpf.emit.bigendian` says: its entry in the section its kind names, every
-- subprogram in `.text`, the maps `luaebpf.maps` holds, and `luaebpf_errors` where a program may
-- stop, in `.maps`, the kfunc a call into the kernel Lua runtime names and those of the iterator a
-- loop calls in `.ksyms`, the bytes a function's code takes the address of in `.data`, but the line
-- of each place a stop counts at, which `.data.luaebpf_errors` holds in the order of the places'
-- entries in `luaebpf_errors`, the license, each function's BTF, and the line info that quotes the
-- Lua line each instruction came from.
-- @module luaebpf.writer

local maps = require("luaebpf.maps")
local structops = require("luaebpf.structops")
local emit = require("luaebpf.emit")
local insn = require("luaebpf.insn")
local elf  = require("luaebpf.elf")
local btf  = require("luaebpf.btf")

local TEXT    <const> = ".text"
local MAPS    <const> = ".maps"
local KSYMS   <const> = ".ksyms"
local DATA    <const> = ".data"
local STRUCTOPS <const> = ".struct_ops"
local BYTE    <const> = 8
local PLACES  <const> = ".data.luaebpf_errors"

local writer = {}

local function readlines(path)
	local file = io.open(path, "r")
	if file == nil then
		return {}
	end
	local lines = {}
	for line in file:lines("l") do
		table.insert(lines, line)
	end
	file:close()
	return lines
end

local function sources(chunk, cache)
	local lines = cache[chunk]
	if lines == nil then
		lines = readlines(chunk)
		cache[chunk] = lines
	end
	return lines
end

local function funcinfo(types, frame, at)
	local params = {}
	for _ = 1, #frame.params do
		table.insert(params, types.long)
	end
	local signature = {result = frame.isprogram and types.int or types.long, params = params}
	local linkage = frame.isprogram and btf.linkage.GLOBAL or btf.linkage.STATIC
	return types:funcinfo(at, types:func(frame.name, linkage, signature))
end

local function lineinfo(types, frame, at, cache)
	local records, lines, previous = {}, frame.code:sourcelines(), nil
	local file = types:string(frame.chunk)
	local text = sources(frame.chunk, cache)
	for i = 1, #lines do
		if lines[i] ~= previous then
			table.insert(records, types:lineinfo(at + (i - 1) * insn.SIZE, file,
				types:string(text[lines[i]] or ""), lines[i], 1))
			previous = lines[i]
		end
	end
	return records
end

-- one blob per ELF section: a program's entry in the section its kind names, which is how
-- libbpf reads the program type back, and every subprogram in ".text", where libbpf resolves a
-- call relocation
local function blob(name)
	return {name = name, code = {}, funcs = {}, lines = {}, relocations = {}, at = 0}
end

local function section(units, sections, name)
	local unit = sections[name]
	if unit == nil then
		unit = blob(name)
		sections[name] = unit
		table.insert(units, unit)
	end
	return unit
end

-- what a function's code names for the object to relocate, each kind with the relocation its
-- instruction takes, in the order the records are written
local relocated = {{kind = "call", type = elf.relocation.IMM32}, {kind = "map", type = elf.relocation.IMM64},
	{kind = "kfunc", type = elf.relocation.IMM32}, {kind = "data", type = elf.relocation.IMM64}}

local function place(types, unit, frame, cache, subprograms)
	local at = unit.at
	table.insert(unit.code, frame.code:pack(emit.bigendian))
	table.insert(unit.funcs, funcinfo(types, frame, at))
	for _, record in ipairs(lineinfo(types, frame, at, cache)) do
		table.insert(unit.lines, record)
	end
	for _, reloc in ipairs(relocated) do
		for _, use in ipairs(frame.code:relocations(reloc.kind)) do
			table.insert(unit.relocations, {at = at + (use.at - 1) * insn.SIZE, name = use.name,
				type = reloc.type})
		end
	end
	unit.at = at + frame.code:len() * insn.SIZE
	if not frame.isprogram then
		table.insert(subprograms, {name = frame.name, section = TEXT, value = at,
			size = frame.code:len() * insn.SIZE, bind = elf.bind.LOCAL, type = elf.type.FUNC})
	end
	return at
end

local function btfsection(object, name, data)
	object:section{name = name, type = elf.section.PROGBITS, flags = 0, data = data, align = 4}
end

-- A BTF-defined map is a struct of pointer-to-array members whose element counts libbpf reads
-- as the map's attributes, a VAR of that struct allocated in ".maps", and one var_secinfo per
-- map in a DATASEC of that name (tools/lib/bpf/libbpf.c). The section's bytes are read only for
-- their length, so zeros of the right size are enough.
local function attributes(map)
	return {{name = "type", value = map.type}, {name = "max_entries", value = map.entries},
		{name = "key_size", value = map.key.size}, {name = "value_size", value = map.value.size}}
end

local function maplayout(object, types, declared)
	if #declared == 0 then
		return {}
	end
	local entries, symbols, at = {}, {}, 0
	for _, map in ipairs(declared) do
		local members = {}
		for _, attribute in ipairs(attributes(map)) do
			table.insert(members, {name = attribute.name,
				type = types:pointer(types:array(types.int, attribute.value))})
		end
		local id, size = types:struct(map.name, members)
		table.insert(entries, {type = types:var(map.name, id), offset = at, size = size})
		table.insert(symbols, {name = map.name, section = MAPS, value = at, size = size,
			bind = elf.bind.GLOBAL, type = elf.type.OBJECT})
		at = at + size
	end
	object:section{name = MAPS, type = elf.section.PROGBITS, flags = elf.flags.ALLOC |
		elf.flags.WRITE, data = ("\0"):rep(at), align = 8}
	types:datasec(MAPS, entries)
	return symbols
end

-- a struct_ops object's bytes: the scalar members at their offsets in a buffer of the struct's
-- whole size, the member that carries a program left zero for the relocation to patch
local function record(size, blocks)
	table.sort(blocks, function(a, b) return a.offset < b.offset end)
	local out, at = {}, 0
	for _, block in ipairs(blocks) do
		table.insert(out, ("\0"):rep(block.offset - at))
		table.insert(out, block.bytes)
		at = block.offset + #block.bytes
	end
	table.insert(out, ("\0"):rep(size - at))
	return table.concat(out)
end

-- The `.struct_ops` section libbpf makes a struct_ops map of: a VAR of the ops struct, allocated in
-- a DATASEC of that name, holding the members the scheduler set; libbpf matches each to the kernel's
-- struct by name (tools/lib/bpf/libbpf.c), so the struct carries only those, at the kernel's own
-- offsets and whole size. A member that carries a program is a pointer the writer relocates to that
-- program's entry, which is why this runs once the entries have addresses. Returns the var symbols
-- and the relocations, each naming the program entry it patches the member to.
local function structopslayout(object, types, declared)
	if #declared == 0 then
		return {}, {}
	end
	local char = types:integer("char", 1, BYTE)
	local entries, symbols, section, relocations, at = {}, {}, {}, {}, 0
	for _, ops in ipairs(declared) do
		local members, blocks = {}, {}
		for _, member in ipairs(ops.members) do
			local id
			if member.program ~= nil then
				id = types:pointer(types:proto{result = types.int, params = member.proto.params})
				table.insert(relocations, {at = at + member.offset, name = member.program.entryname,
					type = elf.relocation.IMM64})
			else
				id = types:array(char, #member.bytes)
				table.insert(blocks, {offset = member.offset, bytes = member.bytes})
			end
			table.insert(members, {name = member.name, type = id, offset = member.offset})
		end
		local id = types:record(ops.struct, members, ops.size)
		table.insert(entries, {type = types:var(ops.name, id), offset = at, size = ops.size})
		table.insert(symbols, {name = ops.name, section = STRUCTOPS, value = at, size = ops.size,
			bind = elf.bind.GLOBAL, type = elf.type.OBJECT})
		table.insert(section, record(ops.size, blocks))
		at = at + ops.size
	end
	object:section{name = STRUCTOPS, type = elf.section.PROGBITS, flags = elf.flags.ALLOC |
		elf.flags.WRITE, data = table.concat(section), align = 8}
	types:datasec(STRUCTOPS, entries)
	return symbols, relocations
end

-- each symbol of `list` in the object, under the name a relocation looks it up by
local function named(object, indexes, list)
	for _, symbol in ipairs(list) do
		indexes[symbol.name] = object:symbol(symbol)
	end
end

-- the bytes a function's code takes the address of, each kept once however many name them, but the
-- lines of the places, which the places keep
local function constants(strings, kept, places, frame)
	for _, use in ipairs(frame.code:relocations("data")) do
		if not kept[use.name] and places[use.name] == nil then
			kept[use.name] = true
			table.insert(strings, use.name)
		end
	end
end

-- a data section, of which libbpf makes an array map whose one value holds the bytes, at the address a
-- program reads them at (tools/lib/bpf/libbpf.c), and a local symbol of each one's offset, named by
-- the bytes, which no function, map or kfunc is
local function datalayout(object, name, strings)
	local symbols, at = {}, 0
	for _, bytes in ipairs(strings) do
		table.insert(symbols, {name = bytes, section = name, value = at, size = #bytes, bind = elf.bind.LOCAL,
			type = elf.type.OBJECT})
		at = at + #bytes
	end
	if at > 0 then
		object:section{name = name, type = elf.section.PROGBITS, flags = elf.flags.ALLOC | elf.flags.WRITE,
			data = table.concat(strings), align = 8}
	end
	return symbols
end

-- the maps of the program file, and the one its stops count in where any check may stop
local function objectmaps(places)
	local list = {table.unpack(maps.declared())}
	if #places > 0 then
		table.insert(list, emit.counts(places))
	end
	return list
end

-- The prototype libbpf compares with the kernel's kind by kind, names and integer widths aside
-- (tools/lib/bpf/relo_core.c): a pointer to an empty struct of the context's name stands for the
-- context, and a pointer to type 0 for the void the argument goes as.
local function prototype(types, context)
	return {result = types.int, params = {types:pointer(types.int), types.long,
		types:pointer((types:struct(context, {}))), types:pointer(0), types.long}}
end

-- the iterator's kfuncs take it by address, which libbpf compares as a pointer to a struct of any
-- layout (kernel/bpf/bpf_iter.c)
local function iterator(types)
	return types:pointer((types:struct("bpf_iter_num", {})))
end

local function iternew(types)
	return {result = types.int, params = {iterator(types), types.int, types.int}}
end

local function iternext(types)
	return {result = types:pointer(types.int), params = {iterator(types)}}
end

local function iterdestroy(types)
	return {result = 0, params = {iterator(types)}}
end

local iterators = {[emit.iterator.new] = iternew, [emit.iterator.next] = iternext,
	[emit.iterator.destroy] = iterdestroy}

local function signature(types, extern)
	local kfunc = iterators[extern.name]
	if kfunc ~= nil then
		return kfunc(types)
	end
	return prototype(types, extern.context)
end

-- each kfunc a call names: a FUNC of extern linkage listed in a DATASEC named ".ksyms", whose bytes
-- libbpf never looks for in the ELF, and the undefined symbol the call's relocation names
local function ksyms(object, types, externs, hook, indexes)
	local entries = {}
	for _, extern in ipairs(externs) do
		local func = types:func(extern.name, btf.linkage.EXTERN, signature(types, extern))
		table.insert(entries, {type = func, offset = 0, size = 0})
		indexes[extern.name] = object:symbol{name = extern.name, value = 0, size = 0, bind = elf.bind.GLOBAL,
			type = elf.type.NOTYPE}
	end
	if #entries > 0 and hook ~= "ksyms" then
		types:datasec(KSYMS, entries)
	end
end

local function reserve(names, declared)
	names[emit.ERRORS] = true
	for _, program in ipairs(declared) do
		if program.kfunc ~= nil then -- a struct_ops callback names no runtime kfunc
			names[program.kfunc] = true
		end
	end
end

local function report(calls, frame)
	for _, call in ipairs(frame.calls) do
		table.insert(calls, string.format("%s:%d: calls the runtime '%s'", frame.chunk, call.line, call.key))
	end
end

-- each kfunc a program's functions call, listed once however many of them do: the runtime's, which
-- takes the context of the program's type, and the iterator's
local function extern(externs, called, program, frame)
	for _, use in ipairs(frame.code:relocations("kfunc")) do
		if not called[use.name] then
			called[use.name] = true
			table.insert(externs, {name = use.name, context = program.context.struct})
		end
	end
end

-- the lines of the places, laid out in their section in the order of their entries, each under the
-- name its stop's relocation looks it up by
local function placelayout(object, indexes, places)
	named(object, indexes, datalayout(object, PLACES, places))
end

---
-- Lowers the programs and writes the object that carries them.
-- @function luaebpf.writer.write
-- @tparam table declared the programs `luaebpf.programs` holds, in declaration order, each named,
--   under the one license they carry
-- @tparam[opt] string hook the mechanism `LUAEBPF_DROP` names, which the object is written without
-- @treturn string the BPF ELF object
-- @treturn table a line per call into the kernel Lua runtime the compiler met, in that order,
--   `<file>:<line>: calls the runtime '<name>'`
-- @raise `<file>:<line>: <reason>` for every construct the subset refuses
function writer.write(declared, hook)
	local object, types, cache = elf.new(emit.bigendian), btf.new(emit.bigendian), {}
	local text = blob(TEXT)
	local units, sections = {text}, {}
	local names, subprograms, order, externs, called, calls = {}, {}, {}, {}, {}, {}
	local strings, kept, places = {}, {}, {}
	-- maps, kfuncs and luaebpf_errors take their names before any function does, so a relocation names one symbol
	for _, map in ipairs(maps.declared()) do
		names[map.name] = true
	end
	reserve(names, declared)
	for _, program in ipairs(declared) do
		program.drop = hook
		program.names = names
		program.places = places
		local entries = section(units, sections, program.section)
		for i, frame in ipairs(emit.program(program)) do
			local unit = i == 1 and entries or text
			local at = place(types, unit, frame, cache, subprograms)
			report(calls, frame)
			extern(externs, called, program, frame)
			constants(strings, kept, places, frame)
			if i == 1 then
				program.entryname = frame.name -- a struct_ops member relocates to this symbol
				table.insert(order, {name = frame.name, section = program.section, value = at,
					size = frame.code:len() * insn.SIZE, bind = elf.bind.GLOBAL,
					type = elf.type.FUNC})
			end
		end
	end

	local indexes = {}
	for _, unit in ipairs(units) do
		if unit.at > 0 then
			object:section{name = unit.name, type = elf.section.PROGBITS,
				flags = elf.flags.ALLOC | elf.flags.EXEC, data = table.concat(unit.code), align = 8}
		end
	end
	local mapsymbols = maplayout(object, types, objectmaps(places))
	local datasymbols = datalayout(object, DATA, strings)
	named(object, indexes, subprograms)
	named(object, indexes, datasymbols)
	placelayout(object, indexes, places)
	for _, entry in ipairs(order) do
		indexes[entry.name] = object:symbol(entry) -- a struct_ops member relocates to a program entry
	end
	named(object, indexes, mapsymbols)
	local structsymbols, structrelocs = structopslayout(object, types, structops.declared())
	named(object, indexes, structsymbols)
	ksyms(object, types, externs, hook, indexes)
	for _, unit in ipairs(units) do
		local records = {}
		for _, call in ipairs(unit.relocations) do
			table.insert(records, {at = call.at, symbol = indexes[call.name], type = call.type})
		end
		if #records > 0 then
			object:relocations(unit.name, records)
		end
	end
	if #structrelocs > 0 then
		local records = {}
		for _, reloc in ipairs(structrelocs) do
			table.insert(records, {at = reloc.at, symbol = indexes[reloc.name], type = reloc.type})
		end
		object:relocations(STRUCTOPS, records)
	end

	object:section{name = "license", type = elf.section.PROGBITS, flags = elf.flags.ALLOC |
		elf.flags.WRITE, data = declared[1].license .. "\0", align = 1}
	local described = {}
	for _, unit in ipairs(units) do
		if unit.at > 0 then
			table.insert(described, {name = unit.name, funcs = unit.funcs,
				lines = hook ~= "lineinfo" and unit.lines or {}})
		end
	end
	local ext = types:ext(described) -- it interns the section names in .BTF's strings, so before pack
	btfsection(object, ".BTF", types:pack())
	btfsection(object, ".BTF.ext", ext)
	return object:pack(), calls
end

return writer

