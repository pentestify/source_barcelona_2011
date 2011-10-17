##
# $Id: xdb_sid.rb 10998 2010-11-11 22:43:22Z jduck $
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
			'Name'        => 'Oracle XML DB SID Discovery',
			'Description' => %q{
					This module simply makes a authenticated request to retrieve
					the sid from the Oracle XML DB httpd server.
			},
			'Version'     => '$Revision: 10998 $',
			'References'  =>
				[
					[ 'URL', 'http://dsecrg.com/files/pub/pdf/Different_ways_to_guess_Oracle_database_SID_(eng).pdf' ],
				],
			'Author'      => [ 'MC' ],
			'License'     => MSF_LICENSE
		)

		register_options(
				[
					Opt::RPORT(8080),
					OptString.new('DBUSER', [ false, 'The db user to authenticate with.',  'scott']),
					OptString.new('DBPASS', [ false, 'The db pass to authenticate with.',  'tiger']),
				], self.class)
	end

	def run_host(ip)
		begin

			user_pass = "#{datastore['DBUSER']}:#{datastore['DBPASS']}"

			res = send_request_raw({
				'uri'     => '/oradb/PUBLIC/GLOBAL_NAME',
				'version' => '1.0',
				'method'  => 'GET',
				'headers' =>
				{
					'Authorization' => "Basic #{Rex::Text.encode_base64(user_pass)}"
				}
			}, 5)

				if( not res )
					print_error("Unable to retrieve SID for #{ip}:#{datastore['RPORT']} with #{datastore['DBUSER']} / #{datastore['DBPASS']}...") if datastore['VERBOSE']
					return
				end

				if (res.code == 200)
					if (not res.body.length > 0)
					# sometimes weird bug where body doesn't have value yet
						res.body = res.bufq
					end
					sid = res.body.scan(/<GLOBAL_NAME>(\S+)<\/GLOBAL_NAME>/)
						report_note(
							:host	=> ip,
							:proto	=> 'tcp',
							:type	=> 'SERVICE_NAME',
							:data	=> "#{sid}"
						)
					print_status("Discovered SID: '#{sid}' for host #{ip}:#{datastore['RPORT']} with #{datastore['DBUSER']} / #{datastore['DBPASS']}")
				else
					print_error("Unable to retrieve SID for #{ip}:#{datastore['RPORT']} with #{datastore['DBUSER']} / #{datastore['DBPASS']}...")
				end
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE
		end
	end
end
