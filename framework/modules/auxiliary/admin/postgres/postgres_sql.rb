##
# $Id: postgres_sql.rb 9306 2010-05-15 03:47:54Z hdm $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Postgres

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'PostgreSQL Server Generic Query',
			'Description'    => %q{
					This module will allow for simple SQL statements to be executed against a
					PostgreSQL instance given the appropiate credentials.
			},
			'Author'         => [ 'todb' ],
			'License'        => MSF_LICENSE,
			'References'     =>
				[
					[ 'URL', 'www.postgresql.org' ]
				],
			'Version'        => '$Revision: 9306 $'
		))

		register_options( [ ], self.class) # None needed.
	end

	def rhost
		datastore['RHOST']
	end

	def rport
		datastore['RPORT']
	end

	def run
		ret = postgres_query(datastore['SQL'],datastore['RETURN_ROWSET'])
		verbose = datastore['VERBOSE']
		case ret.keys[0]
		when :conn_error
			print_error "#{rhost}:#{rport} Postgres - Authentication failure, could not connect."
		when :sql_error
			print_error "#{rhost}:#{rport} Postgres - #{ret[:sql_error]}"
		when :complete
			print_good  "#{rhost}:#{rport} Postgres - Command complete." if verbose
		end
		postgres_logout if self.postgres_conn
	end
end
