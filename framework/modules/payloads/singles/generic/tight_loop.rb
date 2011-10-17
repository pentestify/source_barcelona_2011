##
# $Id: tight_loop.rb 9179 2010-04-30 08:40:19Z jduck $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'msf/core/payload/generic'

module Metasploit3

	include Msf::Payload::Single

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'Generic x86 Tight Loop',
			'Version'       => '$Revision: 9179 $',
			'Description'   => 'Generate a tight loop in the target process',
			'Author'        => 'jduck',
			'Platform'	    => [ 'win', 'linux', 'bsd', 'solaris', 'bsdi', 'osx' ],
			'License'       => MSF_LICENSE,
			'Arch'		    => ARCH_X86,
			'Payload'	    =>
				{
					'Payload' => "\xeb\xfe" # jump to self
				}
			))
	end

end
