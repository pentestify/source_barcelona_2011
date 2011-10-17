##
# $Id: patchupdllinject.rb 9212 2010-05-03 17:13:09Z jduck $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'msf/core/payload/windows/dllinject'

###
#
# Injects an arbitrary DLL in the exploited process.
#
###
module Metasploit3

	include Msf::Payload::Windows::DllInject

end
