##
# $Id: none.rb 9179 2010-04-30 08:40:19Z jduck $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'


class Metasploit3 < Msf::Encoder

	def initialize
		super(
			'Name'             => 'The "none" Encoder',
			'Version'          => '$Revision: 9179 $',
			'Description'      => %q{
				This "encoder" does not transform the payload in any way.
			},
			'Author'           => 'spoonm',
			'License'          => MSF_LICENSE,
			'Arch'             => ARCH_ALL,
			'EncoderType'      => Msf::Encoder::Type::Raw)
	end

	#
	# Simply return the buf straight back.
	#
	def encode_block(state, buf)
		buf
	end

end
