##
# $Id: mssql_sql.rb 13329 2011-07-24 19:36:37Z sinn3r $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::MSSQL

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Microsoft SQL Server Generic Query',
			'Description'    => %q{
					This module will allow for simple SQL statements to be executed against a
					MSSQL/MSDE instance given the appropiate credentials.
			},
			'Author'         => [ 'tebo <tebo [at] attackresearch [dot] com>' ],
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision: 13329 $',
			'References'     =>
				[
					[ 'URL', 'http://www.attackresearch.com' ],
					[ 'URL', 'http://msdn.microsoft.com/en-us/library/cc448435(PROT.10).aspx'],
				]
		))

		register_options(
			[
				OptString.new('SQL', [ false, 'The SQL query to execute',  'select @@version']),
			], self.class)
	end

	def run
		mssql_query(datastore['SQL'], true) if mssql_login_datastore
		disconnect
	end
end
