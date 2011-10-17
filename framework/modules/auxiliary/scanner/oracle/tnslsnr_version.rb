##
# $Id: tnslsnr_version.rb 11128 2010-11-24 19:43:49Z jduck $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner
	include Msf::Exploit::Remote::TNS

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Oracle TNS Listener Service Version Query',
			'Description'    => %q{
				This module simply queries the tnslsnr service for the Oracle build.
			},
			'Author'         => ['CG'],
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision: 11128 $',
			'DisclosureDate' => 'Jan 7 2009'))

		register_options(
			[
				Opt::RPORT(1521)
			], self.class)

		deregister_options('RHOST')
	end

	def run_host(ip)
		begin
			connect

			pkt = tns_packet("(CONNECT_DATA=(COMMAND=VERSION))")

			sock.put(pkt)

			select(nil,nil,nil,0.5)

			data = sock.get_once

				if ( data and data =~ /\\*.TNSLSNR for (.*)/ )
					ora_version = data.match(/\\*.TNSLSNR for (.*)/)[1]
					report_service(
						:host	=> ip,
						:port	=> datastore['RPORT'],
						:name   => "oracle",
						:info   => ora_version
					)
					print_good("#{ip}:#{datastore['RPORT']} Oracle - Version: " + ora_version)
				else
					print_error( "#{ip}:#{datastore['RPORT']} Oracle - Version: Unknown")
				end
			disconnect
		rescue ::Rex::ConnectionError
		rescue ::Errno::EPIPE
		end
	end
end
