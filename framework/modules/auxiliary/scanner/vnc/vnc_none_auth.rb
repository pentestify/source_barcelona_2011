##
# $Id: vnc_none_auth.rb 12623 2011-05-15 22:19:00Z todb $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'rex/proto/rfb'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Tcp
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'        => 'VNC Authentication None Detection',
			'Version'     => '$Revision: 12623 $',
			'Description' => 'Detect VNC servers that support the "None" authentication method.',
			'References'  =>
				[
					['URL', 'http://en.wikipedia.org/wiki/RFB'],
					['URL', 'http://en.wikipedia.org/wiki/Vnc'],
				],
			'Author'      =>
				[
					'Matteo Cantoni <goony[at]nothink.org>',
					'jduck'
				],
			'License'     => MSF_LICENSE
		)

		register_options(
			[
				Opt::RPORT(5900)
			], self.class)
	end

	def run_host(target_host)
		connect

		begin
			vnc = Rex::Proto::RFB::Client.new(sock)
			if not vnc.handshake
				raise RuntimeError.new("Handshake failed: #{vnc.error}")
			end

			ver = "#{vnc.majver}.#{vnc.minver}"
			print_status("#{target_host}:#{rport}, VNC server protocol version : #{ver}")
			report_service(
				:host => rhost,
				:port => rport,
				:proto => 'tcp',
				:name => 'vnc',
				:info => "VNC protocol version #{ver}"
			)

			type = vnc.negotiate_authentication
			if not type
				raise RuntimeError.new("Auth negotiation failed: #{vnc.error}")
			end

			# Show the allowed security types
			sec_type = []
			vnc.auth_types.each { |type|
				sec_type << Rex::Proto::RFB::AuthType.to_s(type)
			}
			print_status("#{target_host}:#{rport}, VNC server security types supported : #{sec_type.join(",")}")

			if (vnc.auth_types.include? Rex::Proto::RFB::AuthType::None)
				print_good("#{target_host}:#{rport}, VNC server security types includes None, free access!")
				report_vuln(
					{
						:host => rhost,
						:port => rport,
						:proto => 'tcp',
						:name	=> self.fullname,
						:info => sec_type.join(","),
						:refs => self.references,
						:exploited_at => Time.now.utc
					})
			end

		rescue RuntimeError
			print_error("#{target_host}:#{rport}, #{$!}")
			raise $!

		ensure
			disconnect
		end

	end
end

