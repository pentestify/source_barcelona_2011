##
# $Id: imap_version.rb 9804 2010-07-13 18:52:27Z todb $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Imap
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'        => 'IMAP4 Banner Grabber',
			'Version'     => '$Revision: 9804 $',
			'Description' => 'IMAP4 Banner Grabber',
			'Author'      => 'hdm',
			'License'     => MSF_LICENSE
		)
	end

	def run_host(ip)
		begin
			res = connect
			banner_sanitized = Rex::Text.to_hex_ascii(banner.to_s)
			print_status("#{ip}:#{rport} IMAP #{banner_sanitized}")
			report_service(:host => rhost, :port => rport, :name => "imap", :info => banner)
		rescue ::Rex::ConnectionError
		rescue ::Exception => e
			print_error("#{rhost}:#{rport} #{e} #{e.backtrace}")
		end
	end

end

