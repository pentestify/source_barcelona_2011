##
# $Id: webdav_website_content.rb 11707 2011-02-04 01:54:32Z todb $
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
			'Name'        => 'HTTP WebDAV Website Content Scanner',
			'Version'     => '$Revision: 11707 $',
			'Description' => 'Detect webservers disclosing its content though WebDAV',
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
				# short url regex
				urlregex = /<a:href[^>]*>(.*?)<\/a:href>/i

				#print_status("#{res.body}")

				result = res.body.scan(urlregex).uniq


				result.each do |u|
					print_status("Found file or directory in WebDAV response (#{target_host}) #{u}")

					report_note(
						:host	=> target_host,
						:proto => 'tcp',
						:sname	=> 'HTTP',
						:port	=> rport,
						:type	=> 'WEBDAV_FILE_DIRECTORY',
						:data	=> "#{u}"
					)

				end
			end

		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE
		end
	end
end

