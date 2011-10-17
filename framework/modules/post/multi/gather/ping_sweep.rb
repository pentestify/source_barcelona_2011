##
# $Id: ping_sweep.rb 13926 2011-10-15 01:37:50Z darkoperator $
##

##
# ## This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'rex'
require 'msf/core/post/common'


class Metasploit3 < Msf::Post

	include Msf::Post::Common


	def initialize(info={})
		super( update_info( info,
				'Name'          => 'Multi Gather Ping Sweep',
				'Description'   => %q{ Performs IPv4 ping sweep using the OS included ping command.},
				'License'       => MSF_LICENSE,
				'Author'        => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>'],
				'Version'       => '$Revision: 13926 $',
				'Platform'      => [ 'windows','linux', 'osx', 'bsd', 'solaris' ],
				'SessionTypes'  => [ 'meterpreter','shell' ]
			))
		register_options(
			[

				OptAddressRange.new('RHOSTS', [true, 'IP Range to perform ping sweep against.']),

			], self.class)
	end

	# Run Method for when run command is issued
	def run
		iprange = datastore['RHOSTS']
		found_hosts = []
		print_status("Performing ping sweep for IP range #{iprange}")
		iplst = []
		begin
			i, a = 0, []
			ipadd = Rex::Socket::RangeWalker.new(iprange)
			numip = ipadd.num_ips
			while (iplst.length < numip)
				ipa = ipadd.next_ip
      			if (not ipa)
        			break
      			end
				iplst << ipa
			end
			if session.type =~ /shell/
				# Only one thread possible when shell
				thread_num = 1
			else
				# When in Meterpreter the safest thread number is 10
				thread_num = 10
			end

			
			iplst.each do |ip|
				# Set count option for ping command
				case session.platform
				when /win/i
					count = " -n 1 " + ip
					cmd = "ping"
				when /solaris/i
					count = " #{ip} 1"
					cmd = "/bin/ping"
				else
					count = " -c 1 #{ip}"
					cmd = "/bin/ping"
				end
				#puts "#{cmd} #{count}"
				if i <= thread_num
					a.push(::Thread.new {
							r = cmd_exec(cmd, count)
							if r =~ /(TTL|Alive)/i
								print_status "\t#{ip} host found"
								report_host({
										:host => ip,
										:comm => "Discovered thru post ping sweep"
									})
							else
								vprint_status("\t#{ip} host not found")
							end

						})
					i += 1
				else
					sleep(0.5) and a.delete_if {|x| not x.alive?} while not a.empty?
					i = 0
				end
			end
			a.delete_if {|x| not x.alive?} while not a.empty?
			
		rescue ::Exception => e
			print_status("The following Error was encountered: #{e.class} #{e}")
			
		end
	end
end