#!/usr/bin/env ruby
require 'mkmf'

if ( RUBY_VERSION =~ /^1\.9/ )
	$CFLAGS += " -DRUBY_19"
end

if (have_library("orcon2", "lorcon_list_drivers", "lorcon2/lorcon.h") or find_library("orcon2", "lorcon_list_drivers", "lorcon2/lorcon.h"))
	create_makefile("Lorcon2")
else
	puts "Error: the lorcon2 library was not found, please see the README"
end
