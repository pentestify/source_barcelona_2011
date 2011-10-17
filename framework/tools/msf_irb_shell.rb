#!/usr/bin/env ruby
#
# $Id: msf_irb_shell.rb 9212 2010-05-03 17:13:09Z jduck $
# $Revision: 9212 $
#

msfbase = File.symlink?(__FILE__) ? File.readlink(__FILE__) : __FILE__
$:.unshift(File.join(File.dirname(msfbase), '..', 'lib'))

require 'rex'
require 'msf/core'
require 'msf/base'
require 'msf/ui'

framework = Msf::Simple::Framework.create

Rex::Ui::Text::IrbShell.new(binding).run