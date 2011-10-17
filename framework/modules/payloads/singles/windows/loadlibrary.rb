##
# $Id: loadlibrary.rb 12765 2011-05-30 03:44:59Z hdm $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'msf/core/payload/windows/loadlibrary'

###
#
# Executes a command on the target machine
#
###
module Metasploit3

	include Msf::Payload::Windows::LoadLibrary

end
