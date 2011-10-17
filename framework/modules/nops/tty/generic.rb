##
# $Id: generic.rb 9179 2010-04-30 08:40:19Z jduck $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'


###
#
# This class implements a "nop" generator for TTY payloads
#
###
class Metasploit3 < Msf::Nop

	def initialize
		super(
			'Name'        => 'TTY Nop Generator',
			'Alias'       => 'tty_generic',
			'Version'     => '$Revision: 9179 $',
			'Description' => 'Generates harmless padding for TTY input',
			'Author'      => 'hdm',
			'License'     => MSF_LICENSE,
			'Arch'        => ARCH_TTY)
	end

	# Generate valid PHP code up to the requested length
	def generate_sled(length, opts = {})
		# Default to just spaces for now
		" " * length
	end

end
