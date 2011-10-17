##
# $Id: smtp_version.rb 9804 2010-07-13 18:52:27Z todb $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Smtp
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'        => 'SMTP Banner Grabber',
			'Version'     => '$Revision: 9804 $',
			'Description' => 'SMTP Banner Grabber',
			'References'  =>
				[
					['URL', 'http://www.ietf.org/rfc/rfc2821.txt'],
				],
			'Author'      => 'CG',
			'License'     => MSF_LICENSE
		)
		deregister_options('MAILFROM', 'MAILTO')
	end

	def run_host(ip)
		begin
			res = connect
			banner_sanitized = Rex::Text.to_hex_ascii(banner.to_s)
			print_status("#{ip}:#{rport} SMTP #{banner_sanitized}")
			report_service(:host => rhost, :port => rport, :name => "smtp", :info => banner)
		rescue ::Rex::ConnectionError
		rescue ::Exception => e
			print_error("#{rhost}:#{rport} #{e} #{e.backtrace}")
		end
	end

end

