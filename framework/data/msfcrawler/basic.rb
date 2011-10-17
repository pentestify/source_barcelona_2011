##
# $Id: basic.rb 9212 2010-05-03 17:13:09Z jduck $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

# $Revision: 9212 $

require 'rubygems'
require 'pathname'
require 'hpricot'
require 'uri'

class CrawlerSimple < BaseParser

	def parse(request,result)

		if !result['Content-Type'].include? "text/html"
			return
		end

		doc = Hpricot(result.body.to_s)
		doc.search('a').each do |link|

		hr = link.attributes['href']

		if hr and !hr.match(/^(\#|javascript\:)/)
			begin
				hreq = urltohash('GET',hr,request['uri'],nil)

				insertnewpath(hreq)

			rescue URI::InvalidURIError
				#puts "Parse error"
				#puts "Error: #{link[0]}"
			end
		end
		end
	end
end

