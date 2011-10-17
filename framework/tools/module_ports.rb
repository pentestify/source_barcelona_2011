#!/usr/bin/env ruby
#
# $Id: module_ports.rb 10652 2010-10-12 15:57:58Z jduck $
#
# This script lists each module by the default ports it uses
#
# $Revision: 10652 $
#

msfbase = File.symlink?(__FILE__) ? File.readlink(__FILE__) : __FILE__
$:.unshift(File.join(File.dirname(msfbase), '..', 'lib'))

require 'rex'
require 'msf/ui'
require 'msf/base'

# Initialize the simplified framework instance.
$framework = Msf::Simple::Framework.create('DisableDatabase' => true)

all_modules = $framework.exploits.merge($framework.auxiliary)
all_ports = {}

all_modules.each_module { |name, mod|
	x = mod.new
	ports = []

	if x.datastore['RPORT']
		ports << x.datastore['RPORT']
	end

	if(x.respond_to?('autofilter_ports'))
		x.autofilter_ports.each do |rport|
			ports << rport
		end
	end
	ports = ports.map{|p| p.to_i}
	ports.uniq!
	ports.sort{|a,b| a <=> b}.each do |rport|
		# Just record the first occurance.
		all_ports[rport] = x.fullname unless all_ports[rport]
	end
}

all_ports.sort.each { |k,v|
	puts "%5s # %s" % [k,v]
}
