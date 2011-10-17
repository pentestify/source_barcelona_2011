##
# $Id: http_version.rb 9579 2010-06-22 01:39:43Z egypt $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'rex/proto/http'
require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	# Exploit mixins should be called first
	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::WMAPScanServer
	# Scanner mixin should be near last
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'        => 'HTTP Version Detection',
			'Version'     => '$Revision: 9579 $',
			'Description' => 'Display version information about each system',
			'Author'      => 'hdm',
			'License'     => MSF_LICENSE
		)

	end

	# Fingerprint a single host
	def run_host(ip)
		begin
			fp = http_fingerprint
			print_status("#{ip} #{fp}") if fp
		rescue ::Timeout::Error, ::Errno::EPIPE
		end
	end

end

