##
## $Id: vm.rb 13744 2011-09-17 03:00:57Z jcran $
##

module Lab
class Vm
	
	attr_accessor :vmid
	attr_accessor :name
	attr_accessor :descripition
	attr_accessor :location
	attr_accessor :driver
	attr_accessor :credentials
	attr_accessor :tools
	attr_accessor :type
	attr_accessor :user
	attr_accessor :host
	attr_accessor :os
	attr_accessor :arch

	## Initialize takes a vm configuration hash of the form
	##  - vmid (unique identifier)
	##    driver (vm technology)
	##    user (if applicable - remote system)
	##    host (if applicable - remote system)
	##    pass (if applicable - remote system)
	##    location (file / uri)
	##    credentials (of the form [ {'user'=>"user",'pass'=>"pass", 'admin' => false}, ... ])
	##    os (currently only linux / windows)
	##    arch (currently only 32 / 64
	
	def initialize(config = {})	

		# TODO - This is a mess. clean up, and pass stuff down to drivers
		# and then rework the code that uses this api. 
		@vmid = config['vmid'].to_s 
		raise "Invalid VMID" unless @vmid

		# Grab the hostname if specified, otherwise use the vmid
		# VMID will be different in the case of ESX
		@hostname = config['hostname']
		if !@hostname
			@hostname = @vmid
		end

		@driver_type = filter_input(config['driver'])
		@driver_type.downcase!

		@location = filter_input(config['location'])
		@name = config['name'] || ""
		@description = config['description'] || ""
		@tools = config['tools'] || ""
		@os = config['os'] || ""			
		@arch = config['arch'] || ""
		@type = filter_input(config['type']) || "unspecified"
		@credentials = config['credentials'] || []
		
		# TODO - Currently only implemented for the first set
		if @credentials.count > 0
			@vm_user = filter_input(@credentials[0]['user']) || "\'\'"
			@vm_pass = filter_input(@credentials[0]['pass']) || "\'\'"
			@vm_keyfile = filter_input(@credentials[0]['keyfile'])
		end

		# Only applicable to remote systems
		@user = filter_input(config['user']) || nil
		@host = filter_input(config['host']) || nil
		@pass = filter_input(config['pass']) || nil

		#Only dynagen systems need this
		@platform = config['platform']

		#Only fog system need this
		@fog_config = config['fog_config']

		# Process the correct driver
		if @driver_type == "workstation"
			@driver = Lab::Drivers::WorkstationDriver.new(config)
		elsif @driver_type == "virtualbox"
			@driver = Lab::Drivers::VirtualBoxDriver.new(config)
		elsif @driver_type == "fog"
			@driver = Lab::Drivers::FogDriver.new(config, config['fog_config'])
		elsif @driver_type == "dynagen"
			@driver = Lab::Drivers::DynagenDriver.new(config, config['dynagen_config'])	
		elsif @driver_type == "remote_esx"
			@driver = Lab::Drivers::RemoteEsxDriver.new(config)
		elsif @driver_type == "remote_workstation"
			@driver = Lab::Drivers::RemoteWorkstationDriver.new(config)
		#elsif @driver_type == "qemu"
		#	@driver = Lab::Drivers::QemuDriver.new	
		#elsif @driver_type == "qemudo"
		#	@driver = Lab::Drivers::QemudoDriver.new	
		else
			raise "Unknown Driver Type"
		end
				
		# Load in a list of modifiers. These provide additional methods
		# Currently it is up to the user to verify that 
		# modifiers are properly used with the correct VM image.
		#
		# If not, the results are likely to be disasterous.
		@modifiers = config['modifiers']
		
		if @modifiers	
 			@modifiers.each { |modifier|  self.class.send(:include, eval("Lab::Modifier::#{modifier}"))}
		end
	end
	
	def running?
		@driver.running?
	end

	def location
		@driver.location
	end

	def start
		@driver.start
	end

	def stop
		@driver.stop
	end

	def pause
		@driver.pause
	end

	def suspend
		@driver.suspend
	end
	
	def reset
		@driver.reset
	end
	
	def resume
		@driver.resume
	end

	def create_snapshot(snapshot)
		@driver.create_snapshot(snapshot)
	end

	def revert_snapshot(snapshot)
		@driver.revert_snapshot(snapshot)
	end

	def delete_snapshot(snapshot)
		@driver.delete_snapshot(snapshot)
	end

	def revert_and_start(snapshot)
		@driver.revert_snapshot(snapshot)
		@driver.start
	end

	def copy_to(from,to)
		@driver.copy_to(from,to)
	end
	
	def copy_from(from,to)
		@driver.copy_from(from,to)
	end
	
	def run_command(command)
		@driver.run_command(command)
	end

	def check_file_exists(file)
		@driver.check_file_exists(file)
	end
	
	def create_directory(directory)
		@driver.create_directory(directory)
	end

	def open_uri(uri)
		# we don't filter the uri, as it's getting tossed into a script 
		# by the driver
		if @os == "windows"
			command = "\"C:\\program files\\internet explorer\\iexplore.exe\" #{uri}"
		else
			command = "firefox #{uri}"
		end

		@driver.run_command(command)
	end

	def to_s
		return "#{@vmid}"
	end

	def to_yaml
		
		# TODO - push this down to the drivers.
		
		# Standard configuration options
		out =  " - vmid: #{@vmid}\n"
		out += "   driver: #{@driver_type}\n"
		out += "   location: #{@location}\n"
		out += "   type: #{@type}\n"
		out += "   tools: #{@tools}\n"
		out += "   os: #{@os}\n"
		out += "   arch: #{@arch}\n"
		
		if @user or @host # Remote vm/drivers only
			out += "   user: #{@user}\n"
			out += "   host: #{@host}\n"
		end

		if @platform
			out += "   platform: #{@platform}\n"
		end

		if @fog_config
			out += @fog_config.to_yaml
		end

		out += "   credentials:\n"
		@credentials.each do |credential|		
			out += "     - user: #{credential['user']}\n"
			out += "       pass: #{credential['pass']}\n"
		end
	
	 	return out
	end
private

	def filter_input(string)
		return "" unless string # nil becomes empty string
		return unless string.class == String # Allow other types
					
		unless /^[(!)\d*\w*\s*\[\]\{\}\/\\\.\-\"\(\)]*$/.match string
			raise "WARNING! Invalid character in: #{string}"
		end

		string
	end
end
end
