##
# $Id: sid_enum.rb 11128 2010-11-24 19:43:49Z jduck $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::TNS
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Oracle TNS Listener SID Enumeration',
			'Description'    => %q{
				This module simply queries the TNS listner for the Oracle SID.
				With Oracle 9.2.0.8 and above the listener will be protected and
				the SID will have to be bruteforced or guessed.
			},
			'Author'         => [ 'CG', 'MC' ],
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision: 11128 $',
			'DisclosureDate' => 'Jan 7 2009'
		))

		register_options(
			[
				Opt::RPORT(1521)
			], self.class)

		deregister_options('RHOST')
	end

	def run_host(ip)
		begin
			connect

			pkt = tns_packet("(CONNECT_DATA=(COMMAND=STATUS))")

			sock.put(pkt)

			select(nil,nil,nil,0.5)

			data = sock.get_once

				if ( data and data =~ /ERROR_STACK/ )
					print_error("TNS listener protected for #{ip}...")
				else
					if(not data)
						print_error("#{ip} Connection but no data")
					else
						sid = data.scan(/INSTANCE_NAME=([^\)]+)/)
							sid.uniq.each do |s|
								report_note(
									:host   => ip,
									:type   => "oracle_instance_name",
									:data   => "PORT=#{rport}, SID=#{s}"
								)
								print_status("Identified SID for #{ip}: #{s}")
							end
						service_name = data.scan(/SERVICE_NAME=([^\)]+)/)
							service_name.uniq.each do |s|
								report_note(
									:host   => ip,
									:type   => "oracle_service_name",
									:data   => "PORT=#{rport}, SERVICE_NAME=#{s}"
								)
								print_status("Identified SERVICE_NAME for #{ip}: #{s}")
							end
					end
				end
			disconnect
		rescue ::Rex::ConnectionError
		rescue ::Errno::EPIPE
		end
	end
end
