##
# $Id: close.rb 13636 2011-08-25 19:07:18Z hdm $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post

	def initialize(info={})
		super( update_info( info,
			'Name'          => 'Multi Generic Operating System Session Close',
			'Description'   => %q{ This module closes the specified session. This can be useful as a finisher for automation tasks },
			'License'       => MSF_LICENSE,
			'Author'        => [ 'hdm' ],
			'Version'       => '$Revision: 13636 $',
			'Platform'      => [ 'linux', 'windows', 'unix', 'osx' ],
			'SessionTypes'  => [ 'shell', 'meterpreter' ]
		))
	end

	def run
		print_status("Closing session #{session.inspect}...")
		session.kill
	end

end

