require "xmlrpc/client"
require "rex"

module Msf
module RPC

# Loosely based on the XMLRPC::ClientS class
# Reimplemented for Metasploit

class Client < ::XMLRPC::Client

	attr_accessor :sock, :token

	# Use a TCP socket to do RPC
	def initialize(info={})

		@buff = ""
		self.sock = Rex::Socket::Tcp.create(
			'PeerHost' => info[:host],
			'PeerPort' => info[:port],
			'SSL'      => info[:ssl]
		)
	end

	# This override hooks into the RPCXML library
	def do_rpc(request,async)

		begin
			self.sock.put(request + "\x00")

			while(not @buff.index("\x00"))
				if ::IO.select([self.sock], nil, nil, 30)
					resp = self.sock.sysread(32768)
					@buff << resp if resp
				end
			end
		rescue ::Exception => e
			self.close
			raise EOFError, "XMLRPC connection closed"
		end

		mesg,left = @buff.split("\x00", 2)
		@buff = left.to_s
		mesg
	end

	def login(user,pass)
		res = self.call("auth.login", user, pass)
		if(not (res and res['result'] == "success"))
			raise RuntimeError, "authentication failed"
		end
		self.token = res['token']
		true
	end

	# Prepend the authentication token as the first parameter
	# of every call except auth.login. Requires the
	def call(meth, *args)
		if(meth != "auth.login")
			if(not self.token)
				raise RuntimeError, "client not authenticated"
			end
			args.unshift(self.token)
		end
		super(meth, *args)
	end

	def close
		self.sock.close rescue nil
		self.sock = nil
	end

end
end
end

