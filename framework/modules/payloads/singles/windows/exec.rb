##
# $Id: exec.rb 9212 2010-05-03 17:13:09Z jduck $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'msf/core/payload/windows/exec'

###
#
# Executes a command on the target machine
#
###
module Metasploit3

	include Msf::Payload::Windows::Exec

end
