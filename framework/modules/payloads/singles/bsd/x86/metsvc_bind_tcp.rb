##
# $Id: metsvc_bind_tcp.rb 8586 2010-02-22 21:05:08Z jduck $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'
require 'msf/core/handler/bind_tcp'
require 'msf/base/sessions/meterpreter_x86_bsd'
require 'msf/base/sessions/meterpreter_options'

module Metasploit3

	include Msf::Payload::Bsd
	include Msf::Payload::Single
	include Msf::Sessions::MeterpreterOptions

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'FreeBSD Meterpreter Service, Bind TCP',
			'Version'       => '$Revision: 8586 $',
			'Description'   => 'Stub payload for interacting with a Meterpreter Service',
			'Author'        => 'hdm',
			'License'       => BSD_LICENSE,
			'Platform'      => 'bsd',
			'Arch'          => ARCH_X86,
			'Handler'       => Msf::Handler::BindTcp,
			'Session'       => Msf::Sessions::Meterpreter_x86_BSD,
			'Payload'       =>
				{
					'Offsets' => {},
					'Payload' => ""
				}
			))
	end

end
