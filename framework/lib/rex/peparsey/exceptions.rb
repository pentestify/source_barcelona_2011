#!/usr/bin/env ruby

# $Id: exceptions.rb 12196 2011-04-01 00:51:33Z egypt $

module Rex
module PeParsey

class PeError < ::RuntimeError
end

class ParseError < PeError
end

class DosHeaderError < ParseError
end

class FileHeaderError < ParseError
end

class OptionalHeaderError < ParseError
end

class BoundsError < PeError
end

class WtfError < PeError
end

class SkipError < PeError
end

end end
