module Msf
module Session
module Provider

###
#
# This interface is to be implemented by a session that is only capable of
# providing an interface to a single command shell.
#
###
module SingleCommandShell

	#
	# Initializes the command shell.
	#
	def shell_init()
		raise NotImplementedError
	end

	#
	# Reads data from the command shell.
	#
	def shell_read(length = nil)
		raise NotImplementedError
	end

	#
	# Writes data to the command shell.
	#
	def shell_write(buf)
		raise NotImplementedError
	end

	#
	# Closes the command shell.
	#
	def shell_close()
		raise NotImplementedError
	end

	#
	# Read data until we find the token
	#
	def shell_read_until_token(token, wanted_idx=0, timeout=10)
		if (wanted_idx == 0)
			parts_needed = 2
		else
			parts_needed = 1 + (wanted_idx * 2)
		end

		# Read until we get the data between two tokens or absolute timeout.
		begin
			::Timeout.timeout(timeout) do
				buf = ''
				idx = nil
				loop do
					if (tmp = shell_read(-1, 2))
						buf << tmp

						# see if we have the wanted idx
						parts = buf.split(token, -1)
						if (parts.length == parts_needed)
							# cause another prompt to appear (just in case)
							shell_write("\n")
							return parts[wanted_idx]
						end
					end
				end
			end
		rescue
			# nothing, just continue
		end

		# failed to get any data or find the token!
		nil
	end

	def shell_command_token(cmd, timeout=10)
		if platform =~ /win/
			output = shell_command_token_win32(cmd, timeout)
		else
			output = shell_command_token_unix(cmd, timeout)
		end
		output
	end

	#
	# Explicitly run a single command and return the output.
	# This version uses a marker to denote the end of data (instead of a timeout).
	#
	def shell_command_token_unix(cmd, timeout=10)
		# read any pending data
		buf = shell_read(-1, 0.01)
		token = ::Rex::Text.rand_text_alpha(32)

		# Send the command to the session's stdin.
		# NOTE: if the session echoes input we don't need to echo the token twice.
		shell_write(cmd + ";echo #{token}\n")
		shell_read_until_token(token, 0, timeout)
	end

	#
	# Explicitly run a single command and return the output.
	# This version uses a marker to denote the end of data (instead of a timeout).
	#
	def shell_command_token_win32(cmd, timeout=10)
		# read any pending data
		buf = shell_read(-1, 0.01)
		token = ::Rex::Text.rand_text_alpha(32)

		# Send the command to the session's stdin.
		# NOTE: if the session echoes input we don't need to echo the token twice.
		shell_write(cmd + "&echo #{token}\n")
		shell_read_until_token(token, 1, timeout)
	end


end

end
end
end
