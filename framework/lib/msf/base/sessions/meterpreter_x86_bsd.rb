##
# $Id: meterpreter_x86_bsd.rb 12196 2011-04-01 00:51:33Z egypt $
##

require 'msf/base/sessions/meterpreter'

module Msf
module Sessions

###
#
# This class creates a platform-specific meterpreter session type
#
###
class Meterpreter_x86_BSD < Msf::Sessions::Meterpreter
	def initialize(rstream, opts={})
		super
		self.platform      = 'x86/bsd'
		self.binary_suffix = 'bso'
	end
end

end
end

