# $Id: tftp.rb 9962 2010-08-06 17:21:22Z jduck $
#
# TFTP Server implementation according to:
#
# RFC1350, RFC2347, RFC2348, RFC2349
#
# written by jduck <jduck [at] metasploit.com>
# thx to scriptjunkie for pointing out option extensions
#

require 'rex/proto/tftp/constants'
require 'rex/proto/tftp/server'
