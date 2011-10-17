##
# $Id: shell_bind_tcp.rb 8621 2010-02-24 20:57:09Z jduck $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'msf/core/payload/generic'
require 'msf/core/handler/bind_tcp'

module Metasploit3

	include Msf::Payload::Single
	include Msf::Payload::Generic

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'Generic Command Shell, Bind TCP Inline',
			'Version'       => '$Revision: 8621 $',
			'Description'   => 'Listen for a connection and spawn a command shell',
			'Author'        => 'skape',
			'License'       => MSF_LICENSE,
			'Handler'       => Msf::Handler::BindTcp,
			'Session'       => Msf::Sessions::CommandShell
			))
	end

end
