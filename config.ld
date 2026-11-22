-- SPDX-FileCopyrightText: (c) 2026 Ring Zero Desenvolvimento de Software LTDA
-- SPDX-License-Identifier: MIT OR GPL-2.0-only

-- LDoc configuration of luaebpf's site, which takes Lunatik's style: the docs workflow checks Lunatik
-- out at .lunatik/, and `ldoc .` writes the site to site/
project = 'luaebpf'
description = 'Lua compiled to eBPF for Lunatik.'
title = 'luaebpf API Documentation'
sort_modules = true
file = {
	'./init.lua',
	'./lib/bpf/map.lua',
	'./lib/bpf/tc.lua',
	'./lib/bpf/vmlinux.lua',
	'./lib/bpf/xdp.lua',
	'./lib/lunatik.lua',
}
dir = 'site'
-- discount renders tables, which the built-in markdown leaves as text
format = 'discount'
-- LDoc writes a backticked name out as <code> before discount runs, so SmartyPants reaches inside it
local unsmart = {ndash = '--', mdash = '---', hellip = '...'}
postprocess_html = function(html)
	return (html:gsub('<code>(.-)</code>', function(code)
		return '<code>' .. code:gsub('&(%a+);', unsmart) .. '</code>'
	end))
end
style = './.lunatik/doc/style'
template = './.lunatik/doc/style'
-- the template renders README.md as the home page and the other topics as the guide
topics = {
	'README.md',
	'./doc/guide/08-luaebpf.md',
	'./doc/guide/09-luaebpf-by-example.md',
}
use_markdown_titles = true
manual_url 'https://www.lua.org/manual/5.5/manual.html'
boilerplate = true
merge = true
sort = true

-- what the site's template reads of this project
vars = {
	github = 'https://github.com/luainkernel/luaebpf',
	headline = {'XDP and TC programs', 'written in Lua'},
	donate = 'https://luainkernel.github.io/lunatik/index.html#support',
	areas = {
		{'compiler', 'Compiler', 'Compiling a program file into a BPF object.',
			{'^luaebpf$'},
			'M8 6l-6 6 6 6M16 6l6 6-6 6'},
		{'declarations', 'Program file', 'The modules a program file\'s body requires to declare what the object carries.',
			{},
			'M4 4h16v16H4zM8 9h8M8 13h8M8 17h5'},
	},
}
