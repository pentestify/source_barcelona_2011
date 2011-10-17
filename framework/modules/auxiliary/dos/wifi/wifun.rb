##
# $Id: wifun.rb 9179 2010-04-30 08:40:19Z jduck $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Lorcon2
	include Msf::Auxiliary::Dos

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Wireless Test Module',
			'Description'    => %q{
				This module is a test of the wireless packet injection system.
			Please see external/ruby-lorcon/README for more information.
			},

			'Author'         => [ 'hdm' ],
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision: 9179 $'
		))
	end

	def run
		open_wifi
		wifi.write("X" * 1000)
	end

end
