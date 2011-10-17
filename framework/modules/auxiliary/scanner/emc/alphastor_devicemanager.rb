##
# $Id: alphastor_devicemanager.rb 11127 2010-11-24 19:35:38Z jduck $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Tcp
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'           => 'EMC AlphaStor Device Manager Service',
			'Version'        => '$Revision: 11127 $',
			'Description'    => 'This module querys the remote host for the EMC Alphastor Device Management Service.',
			'Author'         => 'MC',
			'License'        => MSF_LICENSE
		)

		register_options([Opt::RPORT(3000),], self.class)
	end


	def run_host(ip)

		connect

		pkt = "\x68" + Rex::Text.rand_text_alphanumeric(5) + "\x00" * 512

		sock.put(pkt)

		select(nil,nil,nil,0.25)

		data = sock.get_once

		if ( data and data =~ /rrobotd:rrobotd/ )
				print_status("Host #{ip} is running the EMC AlphaStor Device Manager.")
				report_service(:host => rhost, :port => rport, :name => "EMC AlphaStor Device Manager", :info => data)
		else
				print_error("Host #{ip} is not running the service...")
		end

		disconnect

	end
end
