##
# $Id: ifs.rb 9179 2010-04-30 08:40:19Z jduck $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'


class Metasploit3 < Msf::Encoder

	# Below normal ranking because this will produce incorrect code a lot of
	# the time.
	Rank = LowRanking

	def initialize
		super(
			'Name'             => 'Generic ${IFS} Substitution Command Encoder',
			'Version'          => '$Revision: 9179 $',
			'Description'      => %q{
				This encoder uses standard Bourne shell variable substitution
				to avoid spaces without being overly fancy.
			},
			'Author'           => 'egypt',
			'Arch'             => ARCH_CMD)
	end


	#
	# Encodes the payload
	#
	def encode_block(state, buf)
		buf.gsub!(/\s/, '${IFS}')
		return buf
	end

end
