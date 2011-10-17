#!/usr/bin/env ruby
#
# $Id: pattern_create.rb 9212 2010-05-03 17:13:09Z jduck $
# $Revision: 9212 $
#

$:.unshift(File.join(File.dirname(__FILE__), '..', 'lib'))

require 'rex'

if (!(length = ARGV.shift))
	$stderr.puts("Usage: #{File.basename($0)} length [set a] [set b] [set c]\n")
	exit
end

# If the user supplied custom sets, use those.  Otherwise, use the default
# sets.
sets = ARGV.length > 0 ? ARGV : Rex::Text::DefaultPatternSets

puts Rex::Text.pattern_create(length.to_i, sets)
