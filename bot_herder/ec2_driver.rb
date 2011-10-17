require 'vm_driver'
require 'net/ssh'
require 'net/scp'
#require 'rubygems'

##
## $Id$
##

module Lab
module Drivers

class Ec2Driver < VmDriver

	attr_accessor :type
	attr_accessor :location

	def initialize		
		@base_ami = "ami-e3eb2d8a" 
		
		@priv_key = "/home/willis/Projects/AWS/ec2-keypair.pem" #public_key 
		@private_key = "/home/willis/Projects/AWS/pk-UVWBY2DLUDID3AZSKDEBSE46AAC5MQ4O.pem" #private_key
		@cert = "/home/willis/Projects/AWS/cert-UVWBY2DLUDID3AZSKDEBSE46AAC5MQ4O.pem"
		
		@aws_access_key = IO.read("/home/willis/Projects/AWS/ACCESS_KEY").chomp
		@aws_secret_key = IO.read("/home/willis/Projects/AWS/SECRET_KEY").chomp

		@ec2_region="us-east-1"
	end

	def start
		details = `ec2-run-instances -K #{@private_key} -C #{@cert} #{@base_ami}`
		bot_attributes = details.split("\t")
		details.each do |detail|
			puts "instance : #{detail}" if detail =~ //
		end
          #an equiv call can be made using a get request
          #
          
	end
	
	def start_api
	   digest = HMAC::SHA1.new(@aws_secret_key)
	   #digest << string_to_sign
	   #StringToSign = HTTPVerb + "\n" + ValueOfHostHeaderInLowercase + "\n" + HTTPRequestURI + "\n" + CanonicalizedQueryString <from the preceding step>
	   #e.g.
	   # string_to_sign = "GET \n ec2.us-east-1.amazonaws.com \n / Action=RunInstances&ImageId=ami-60a54009&MaxCount=3&MinCount=1&Placement.AvailabilityZone=us-east-1b&Monitoring.Enabled=true&AWSAccessKeyId=0GS7553JW74RRM612K02EXAMPLE&​Version=2011-05-15​&Expires=2010-10-10T12:00:00Z​&Signature=lBP67vCvGlDMBQ1do​fZxg8E8SUEXAMPLE&SignatureVersion=2&SignatureMethod=HmacSHA256
	   #Base64.encode64(digest.digest)
	end
	
	def start_multiple(n)
          (1..n).each do |i|
          `ec2-run-instances -K #{@private_key} -C #{@cert} #{@base_ami}` 
          end
	end

	def stop
		
	end

	def suspend
		raise "unimplemented"
	end

	def pause
		raise "unimplemented"
	end

	def reset
		raise "unimplemented"
	end

	def create_snapshot(snapshot)
		raise "unimplemented"
	end

	def revert_snapshot(snapshot)
		raise "unimplemented"
	end

	def delete_snapshot(snapshot)
		raise "unimplemented"
	end

	def run_command(command, ip)
		puts "\nRunning #{command.to_s.chomp} \t \t #{ip.chomp} \t \t #{Time.new} \t #{@priv_key}"
		user = "ubuntu"
	        Net::SSH.start(ip.chomp, user,                   
                   :keys => "#{@priv_key}",
                   :auth_methods => "publickey",
                   :paranoid => false,
                   :user_known_hosts_file => "/home/willis/AWS/known_hosts"
                   ) do |ssh|
          
			ssh.open_channel do |channel|
			    channel.exec(command.to_s.chomp) do |ch, success|
				abort "could not execute command" unless success

				channel.on_data do |ch, data|
					puts "#{data}"
            
				# could add in the ability to send stuff here
				#channel.send_data "something for stdin\n"
				end
	
				channel.on_extended_data do |ch, type, data|
					puts "#{data}"
				end

				channel.on_close do |ch|
					puts "Closing the connection to #{ip}..\n"
				end
			end
		end
	        end
	end
	        
	def run_command_multi_thread(command,ips)
		threads = []
		(1..ip.size).each do |i|
			threads << Thread.new(i) { |myPage|  

				puts "\nRunning #{command.to_s.chomp} \t \t #{ip.chomp} \t \t #{Time.new}"

			        ::Net::SSH.start(ip, 'ubuntu',
		                   :auth_methods => "publickey",
		                   :keys => "#{@priv_key}",
		                   :paranoid => false,
		                   :user_known_hosts_file => "/home/willis/AWS/known_hosts") do |ssh|
          
					ssh.open_channel do |channel|
						channel.exec(command.to_s.chomp) do |ch, success|
							abort "could not execute command" unless success
	
							channel.on_data do |ch, data|
								puts "#{data}"
            
							# could add in the ability to send stuff here
							#channel.send_data "something for stdin\n"
							end
		
							channel.on_extended_data do |ch, type, data|
								puts "#{data}"
							end

							channel.on_close do |ch|
								puts "Closing the connection to #{ip}..\n"
							end
						end
					end
				end
			}
		end
		threads.each { |aThread|  aThread.join }
		
	end
	
	def scp_file(user, ip, file, dest)
		Net::SCP.upload!(ip, user,
			file.to_s, dest)
	end
	
	def retrieve_file(from, to)
		raise "unimplemented"
	end

	def check_file_exists(file)
		raise "unimplemented"
	end

	def create_directory(directory)
		raise "unimplemented"
	end

	def cleanup
		raise "unimplemented"
	end

	def running?
		raise "unimplemented"
	end
	
	def list_ips
		running_ips = []
	        `ec2-describe-instances -K #{@private_key} -C #{@cert}`.each_line { |line|
			   running_ips << $1.gsub('-','.') if line =~ /\bec2-([0-9-]+)/
			}	        
		return running_ips
	end

end
end
end
