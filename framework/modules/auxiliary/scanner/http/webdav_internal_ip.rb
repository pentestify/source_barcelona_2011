##
# $Id: webdav_internal_ip.rb 11796 2011-02-22 20:49:44Z jduck $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	# Exploit mixins should be called first
	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::WMAPScanServer
	# Scanner mixin should be near last
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'        => 'HTTP WebDAV Internal IP Scanner',
			'Version'     => '$Revision: 11796 $',
			'Description' => 'Detect webservers internal IPs though WebDAV',
			'Author'       => ['et'],
			'License'     => MSF_LICENSE
		)

	end

	def run_host(target_host)

		begin
			res = send_request_cgi({
				'uri'          => '/',
				'method'       => 'PROPFIND',
				'data'	=>	'',
				'ctype'   => 'text/xml',
				'version' => '1.0',
				'vhost' => '',
			}, 10)


			if res and res.body
				# short regex
				intipregex = /(192\.168\.[0-9]{1,3}\.[0-9]{1,3}|10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/i

				#print_status("#{res.body}")

				result = res.body.scan(intipregex).uniq


				result.each do |addr|
					print_status("Found internal IP in WebDAV response (#{target_host}) #{addr}")

					report_note(
						:host	=> target_host,
						:proto => 'tcp',
						:sname	=> 'HTTP',
						:port	=> rport,
						:type	=> 'INTERNAL_IP',
						:data	=> "#{addr}"
					)
				end
			end

		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE
		end
	end
end

