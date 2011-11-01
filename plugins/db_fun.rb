##
## $Id$
##

module Msf

class Plugin::DbFun < Msf::Plugin
	class DbFunCommandDispatcher
		include Msf::Ui::Console::CommandDispatcher
		
		def initialize(driver)
			super(driver)
			@working_set = []
			@sets = {}
			@debug = true
			@output = driver.output
			@input = driver.input
		end
		
		attr_accessor :debug
		
		def print_deb(msg='')
			print_line("%bld%mag[debug]%clr #{msg}") if @debug
		end

		# TODO:  Turn a set into it's own class?  I guess it already has a class from DbManager?

		#
		# Returns the hash of commands supported by this dispatcher.
		#
		def commands
		{
			"db_search" => "db_search [type] [ WHERE [sub_type] CONTAINS [column]=[value] [OR ...] ] - Find database items",
			"db_set_list" => "List all sets",
			"db_set_show" => "[id] - Show the set",
			"db_set_create" => "[id] - Set this query as the current db working set.",
			"db_set_auto" => "Automatically create some default sets like: windows,linux,all_hosts,etc",
			"db_set_add_to" =>  "[id] - Add these items to the working set",
			"db_set_del_from" => "[id] - Delete these items to the working set",	
			"db_set_run_module" => "[id] module [payload] [OPT=val] # run module against set",
			"db_fun_show_examples" => "I'm confused, show me some examples",
			"db_fun_debug" => "db_fun_debug [true|false] # sets or displays debug setting",
		}
		end

		def name
			"DbFun"
		end


		##
		## Regular Commands
		##

		# TODO:  Maybe, around alias the core framework's cmd_db_status with old_cmd_db_status and
		#			redefine cmd_db_status to also include the sets, might need something in clenaup
		#			to unalias?  Something like:
		#alias old_cmd_db_status cmd_db_status
		#def cmd_db_status(*args)
		#	old_cmd_db_status(args)
        #	if framework.db.driver
        #		if ActiveRecord::Base.connected? and ActiveRecord::Base.connection.active?
        #			if ActiveRecord::Base.connection.respond_to? :current_database
        #				cdb = ActiveRecord::Base.connection.current_database
        # 			end
        #			print_status("Database has the following sets:\nself.cmd_db_set_list")
		#		end
		#	end
        #end
        
		def cmd_db_fun_show_examples()
			examples = {
			:db_search => [ "db_search hosts where os_name~windo",
							"db_search hosts where os_name=linux",
							"db_search services where proto=tcp",
							"db_search sessions where closed_at=nil" ],
			"db_set_create" => "db_set_create 1  # creates db set with id 1 using latest query",
			"db_set_add_to" =>  "db_set_add_to 1  # adds to db set 1 using latest query results",
			"db_set_run_module" => "db_set_run_module windows scanner/smb/smb_version # run mod against set 'windows'",
			}
			#just do a simple display for now
			print_good "db_fun command examples"
			examples.each_value do |val|
				print_line("   #{val}")
			end
		end

		def cmd_db_set_list(*args)
			return fun_usage unless args.count == 0
	
			show_all_sets
		end

		# print it dood
		def cmd_db_set_show(*args)
			if args.count == 0
				hlp_print_set @working_set, "Working Set" 
			else
				set_id = args[0]
				if @sets.include?(set_id)
					hlp_print_set @sets[set_id], "Set #{set_id}"
				else
					print_error "The provided set (#{set_id}) was not found in:"
					show_all_sets
				end
			end		
		end	

		def cmd_db_search(*args)
			return fun_usage unless args.count > 0
			#TODO:  Add support for searching for an empty or nil column value
			result_set = self.dbsearch(args)
			if result_set.length > 0
				hlp_print_set(result_set, "Searched Set")
			else
				print_error "Your search did not return any results"
			end
		end
		
		def cmd_db_fun_debug(bool=nil)
			if bool =~ /^f/i # if it even starts with "f/F"
				@debug = false
			elsif bool =~ /^t/i
				@debug = true
				print_good "Debugging information will now be displayed"
			elsif bool.nil?
				print_good "Debug is set to #{@debug.to_s}"
			else
				print_error "I didn't recognize your argument, try true, false, or no arguments"
			end
			@debug
		end

		def cmd_db_set_run_module(*args)
			# expects:  [set_id] [module] [payload] [options(OPT=val format)]
			
			fmwk = self.framework || Msf::Simple::Framework.create
			if args.count > 0
				mod_args = {}
				mod_opts = {}
				mod_args[:set] = @working_set # default
				if @sets.has_key?(args[0])
					# if the first arg seems to be a key in @sets, assume it's a set_id and resolve it
					print_deb "#{args[0]} looks like a set id"
					begin
						mod_args[:set] = @sets[args[0]] 
						args.shift
					rescue Error => e
						print_error "Invalid Set!"
						print_error "e.backtrace"
						show_all_sets
					end
				end
				
				modjool = self.normalize_module(args[0])
				if fmwk.modules.include?(modjool)
					print_deb "Module (#{modjool}) is valid."
					# if this arg matches a known module, assume it's a module
					mod_args[:module] = modjool
					args.shift # this doesn't throw an error if args is empty
				else
					raise ArgumentError.new ("The module or set id (#{modjool}) is not valid.")
				end
				
				if fmwk.payloads.include?(args[0])
					# if this arg matches a known payload, assume it's a payload
					mod_args[:payload] = args[0]
					args.shift # this doesn't throw an error if args is empty
				end
				# now process the remaining args as options if any args remain
				while args.count > 0
					print_deb "Parsing remaining module option: #{args[0]}"
					# be nice: allow '=' or '==' etc and let them put "=" in the value
					opt,val = args[0].split(/=+/,2)
					print_deb "opt and val parsed as #{opt} and #{val}"
					mod_opts[opt.to_s.upcase] = val.to_s.downcase #downcase everything for now
					# not using symbols above as it seems to break the framework
					args.shift
				end

				print_deb("Attemping to run: #{mod_args[:module]} #{mod_args[:payload]}, " +
							"with options: #{mod_opts.to_s}")
				self.run_module(fmwk,mod_args,mod_opts)
			else 
				print_error "Set some options chief!"
				return fun_usage
			end		
		end

		def cmd_db_set_create(*args)
			#TODO:  Find a way to persist sets by serializing? them to .msf4 etc
			#TODO:  Decide whether or not to be case sensitive and enforce it
			return fun_usage unless args.count > 0	
		
			set_id = args[0]
			if @working_set
				@sets[set_id] = @working_set
			else
				print_error "Search for something so working set will have something in it!"
			end
		end
		
		# Automatically create some default sets such as windows, linux, all_hosts, all_services etc
		def cmd_db_set_auto
			#TODO:  Find a way to persist sets by serializing? them to .msf4 etc
			self.create_set("windows", "hosts where os_name~windows")
			self.create_set("linux", "hosts where os_name~linux")
			self.create_set("all_hosts", "hosts")
			self.create_set("all_active_sessions", "sessions where closed_at=nil")
			self.create_set("unknown", "hosts where os_name=nil")
			cmd_db_set_list
		end
		
		# Merge the two sets
		def cmd_db_set_add_to(*args)
			return fun_usage unless args.count > 0
			
			set_id = args[0]
			@sets[set_id].merge!(@working_set)
		end

		# This method just loops through our named set, and each
		# item of the working set for each item, removing if they're
		# the same.
		def cmd_db_set_del_from(*args)
			set_id = args[0]
			@sets[set_id].each do |item|
				@working_set.each do |working_item|
					if @working_item == item
						@sets[set_id].remove!(item)
					end
				end
			end
		end
		
		protected
		#
		# Determines what we will treat as "nil-like" values
		# This will hopefully give the user some flexbility in searching for "nil"
		#
		def is_nil_like?(val=nil)
			val = val.to_s if val.respond_to?("to_s")
			# let's be explicit here:
			return true if (val.nil? or val =~ /^\s$/ or val.empty? or val.downcase == "nil")
			false
		end
		#
		# Actually creates a db set
		#
		def create_set(set_id,search_str)
			args = search_str.split(" ")
			self.dbsearch(args)
			self.cmd_db_set_create(set_id)
		end
		
		#
		# Normalize module names/paths
		#
		def normalize_module(m)
			raise ArgumentError.new "Could not normalize module, no module given" unless m
			# TODO:  Improve this ghetto crap
			# remove any leading slashes and any leading words like auxiliary or post etc
			modjool = m.downcase
			modjool.gsub!(/^[\\\/]+/,'') # this is supposed to get rid of leading slashes
			#print_deb "modjool with leading slashes stripped: #{modjool}"
			modjool.gsub!(/^auxiliary|^encoders|^exploit[s]*|^nops|^payloads|^post/,'')
			modjool.gsub!(/^[\\\/]+/,'') # this is supposed to get rid of leading slashes
			#print_deb "modjool with leading module types stripped: #{modjool}"
			return modjool
		end
		
		#
		# This method actually runs a module against a set, meant to be called by db_set_run_module etc
		#
		def run_module(framework=nil,args={},opts={})
			# possible args - :set :module :payload
			# possible opts - :rhost :lhost :lport :rport etc
			#print_deb "The set is #{args[:set].to_s}"
			# TODO:  Merge in some good default option settings like VERBOSE => false etc
			if (args.class != Hash or args.empty?)
				raise ArgumentError.new ("Expected:  framework=nil, args={}, and optionally opts={}")
			end
			# make sure all keys in opts are strings and not symbols, symbols seem to break
			opts.each_key do |k|
				# TODO:  convert to string or raise error if symbol?
			end
			#create a framework instance if need be
			framework = Msf::Simple::Framework.create unless framework
			raise("No framework object given and unable to instantiate a new framework.  ") unless framework
			#check if leading aux, post, exploit, modules
			# remove any leading slashes and any leading words like auxiliary or post etc
			args[:module] = self.normalize_module(args[:module])
			# let's get an instance of the module
			if framework.modules.include?(args[:module])
				inst = framework.modules.create(args[:module])
			else
				raise ArgumentError.new ("#{args[:module]} is not a valid module")
			end
			it = inst.type
			print_deb "Number of items in the set = #{args[:set].count}"
			print_deb "Running #{it} module with framework:#{framework} args:#{args} opts:#{opts}"
			
			case it
			when /auxiliary/
				self.run_aux(inst,args,opts)
			when /post/
				#print_error "post modules are not supported yet"
				self.run_post(inst,args,opts)
			when /exploit/
				self.run_exploit(inst,args,opts)
			when /payload/
				raise ArgumentError.new ("Can't have a payload as the module")
			when /encoder|nop/
				raise ArgumentError.new ("Not feasible to use a nop or encoder as the module")
			else
				print_deb "The module type (#{inst.type}) must be new cuz it's valid, but I don't recognize"
			end
						# TODO:  check if most aux/post mods write to the db, otherwise report
						# aux.report_note({
						#		:data => "required" #whatever it is you're making a note of
						#		:type => "required" # type of note, e.g. smb_peer_os
						# 		:workspace => "optional" # workspace to associate w/note
						#		:host => item.address #IP address or Host obj to assoc.
						#		:service => "optional" #Service object to assoc.
						#		:port => "optional" along w/ :host & proto, a service to assoc w/ this Note
						#		:proto => "optional" along w/ :host & port, a service to assoc w/ this Note
						#		:update => what to do in case a similar Note exists
								# The +:update+ option can have the following values:
								#unique+::allow only a single Note per +:host+/+:type+ pair
								#:unique_data+::like +:uniqe+, but also compare +:data+
								#:insert+::always insert a new Note regardless
						#				})


		end
		
		def run_aux(inst, args={}, opts={})
			# TODO:  Do we need validation of args this far down in the call stack?
			if args[:set].count > 0
				args[:set].each do |item| 
					if item.class == Msf::DBManager::Host
						print_good "Running #{inst.name} against #{item.address}"
						#`
						# Do it like a boss d-_-b
						#
						# TODO:  it's probably a good idea to consolidate RHOSTS at some point
						#  to avoid calling the same module repeatedly for each ip, instead of once
						#  for now let's just keep it simple
						opts[:RHOSTS.to_s] = item.address # must use string as key, datastore cranky
						begin
							# Move print_deb input and output to after run_simple?
							inst.run_simple(
								'Payload'     	=> args[:payload],
								'Options'		=> opts,
								'LocalInput'	=> @input,
								'LocalOutput'	=> @output,
								#'LocalInput'	=> Rex::Ui::Text::Input::Buffer.new,
								#'LocalOutput'	=> Rex::Ui::Text::Output::Buffer.new,
								#'RunAsJob'		=> true
											)
						rescue Exception => e
							raise ArgumentError.new("Unable to run #{args[:module]}, check " +
							"required options\n" + "#{e.backtrace}")
						end
					else 
						print_error "#{item.class} is not a host!"
					end # end if
				end # end each
			else
				print_error "Nothing in the set!" 
			end # end if
		end # end method
		
		def run_post(inst, args={}, opts={})
			# TODO:  Do we need validation of args this far down in the call stack?
			
			# run against any sessions matching our set (service or host) or a sessions set?
			# TODO:  support hosts and services, but convert them to any live sessions
			# for now, the set must be of type Session
			
			if args[:set].count > 0
				args[:set].each do |item| 
					if item.class == Msf::DBManager::Session
						print_good "Running #{inst.name} against session #{item.local_id}" #TODO:  host,address,id?
						#`
						# Do it like a boss d-_-b
						#

						opts[:SESSION.to_s] = item.local_id # must use string as key, datastore cranky
						begin
							inst.run_simple(
								#'Payload'     	=> args[:payload],
								'Options'		=> opts,
								'LocalInput'	=> @input,
								'LocalOutput'	=> @output,
								#'LocalInput'	=> Rex::Ui::Text::Input::Buffer.new,
								#'LocalOutput'	=> Rex::Ui::Text::Output::Buffer.new,
								#'RunAsJob'		=> true
											)
						rescue Exception => e
							raise ArgumentError.new("Unable to run #{args[:module]}, check " +
							"required options\n" + "#{e.backtrace}")
						end
					else 
						print_error "#{item.class} is not a session!"
					end # end if
				end # end each
			else
				print_error "Nothing in the set!" 
			end # end if
			
			# NOTES:  
			#
			#  Session Info: lib/msf/ui/console/command_dispatcher/core.rb
			#print(Serializer::ReadableText.dump_sessions(framework, :verbose => verbose))
=begin
				cmds.each do |cmd|
					if sid
						sessions = [ sid ]
					else
						sessions = framework.sessions.keys.sort
					end
					sessions.each do |s|
						session = framework.sessions.get(s)
						print_status("Running '#{cmd}' on #{session.type} session #{s} (#{session.tunnel_peer})")

						if (session.type == "meterpreter")
							# If session.sys is nil, dont even try..
							if not (session.sys)
								print_error("Session #{s} does not have stdapi loaded, skipping...")
								next
							end
							c, c_args = cmd.split(' ', 2)
							begin
								process = session.sys.process.execute(c, c_args,
									{
										'Channelized' => true,
										'Hidden'      => true
									})
							rescue ::Rex::Post::Meterpreter::RequestError
								print_error("Failed: #{$!.class} #{$!}")
							end
							if process and process.channel and (data = process.channel.read)
								print_line(data)
							end
						elsif session.type == "shell"
							if (output = session.shell_command(cmd))
								print_line(output)
							end
						end
						# If the session isn't a meterpreter or shell type, it
						# could be a VNC session (which can't run commands) or
						# something custom (which we don't know how to run
						# commands on), so don't bother.
					end
				end
=end		#
			
		end # end method
		
		def run_exploit(inst, args={}, opts={})
			print_deb "self has class of #{self.class} and is #{self}"
			raise ArgumentError.new ("Missing payload") unless args[:payload]
			# TODO:  Do we need validation of other args this far down in the call stack?
			# TODO:  Need to be able to handle TARGETS (os_name?), what else?
			if args[:set].count > 0
				args[:set].each do |item| 
					if item.class == Msf::DBManager::Host # TODO this could be service too maybe?
						print_good "Running #{inst.name} against #{item.address}"
						#
						# Do it like a boss d-_-b
						#
						# If exploit mods ever supported RHOSTS, we could consolidate RHOSTS...
						opts[:RHOST.to_s] = item.address # must use string as key, datastore cranky
						begin
							ex = inst.exploit_simple(
									'Payload'     => args[:payload],
									'Options'		=> opts,
									'LocalInput'	=> @input,
									'LocalOutput'	=> @output,
									#'RunAsJob'		=> true
												)
									#inst.session_created?
									#inst.session_count
									ex.session.load_stdapi if ex and ex.session_created?
									#session.load_stdapi

						rescue Exception => e
							raise ArgumentError.new("Unable to run #{args[:module]}, check " +
							"required options\n" + "#{e.backtrace}")
							# could show datastore here
						end
					else 
						print_error "#{item.class} is not a host!"
					end # end if
				end # end each
			else
				print_error "Nothing in the set!" 
			end # end if
		end # end method
				
		# perform the actual search and return the matching set
		def dbsearch(args=[])
			# Make sure we form the class name correctly
			class_name = args[0].downcase
			class_name[0] = class_name[0].capitalize
			class_name = class_name.singularize
						
			print_deb ("Class name:  #{class_name}")
			 
			begin
				eval("Msf::DBManager::#{class_name}.respond_to?(:find)")
			rescue
				print_error "Error while querying database. Make sure this table"
				print_error "and column combination actually exists in the database."
				return
			end
			
			if args.count == 1
				@working_set = eval("Msf::DBManager::#{class_name}.all")
		  	else
				filters = []
				sub_items_list = []
				@working_set = []			
		
				args.shift ## drop the table from the string		
				
				# Parse argument string
				args.each_with_index do |arg,i|
				
					print_deb "parsing arg #{arg}"
				
					if arg.downcase =~ /where/
						filters << args[i+1]
					end
					
					if arg.downcase =~ /or/
						filters << args[i+1]
					end
					
					if arg.downcase =~ /contain/
						sub_items_list << args[i-1]
						filters.pop # remove the last item from the filter
						filters << args[i+1]
					end
				end

				# Go get the items
				query_string = "Msf::DBManager::#{class_name}.all"
				item_set = eval(query_string)
				
				### 
				## 	Parse filters
				###
				equal_conditions = {}
				match_conditions = {}
	
				filters.each do |filter|
				
					# Split based on the delimiter
					if filter =~ /=/
						equal_condition = filter.split("=")
						#equal_condition[-1] = nil if equal_condition[-1] = "nil"
						equal_conditions[equal_condition.first] = equal_condition.last
					end


					# Split based on the delimiter
					if filter =~ /~/
						match_condition = filter.split("~")
						match_conditions[match_condition.first] = match_condition.last
					end	
				end	

				print_good "Searching for #{class_name} with conditions..."

				# Tell the user what their filter looks like
				equal_conditions.each_pair do |key,val|
					print_good "Exact: #{key} = #{val}"
				end

				# Tell the user what their filter looks like
				match_conditions.each_pair do |key,val|
					print_good "Match: #{key} =~ /#{val}/"
				end
				
				### 
				## 	End Parsing
				###

				###
				##   	Get the right collection if we include sub-items
				###
				while sub_items_list.count > 0 do
					sub_items = sub_items_list.shift
					print_deb "Handling a sub item : #{sub_items}!"
					#item_set = eval("item.#{sub_items}")
					temp_item_set = []
					item_set.each do |item|
						temp_item_set = temp_item_set + (eval("item.#{sub_items}"))
					end					
					item_set = temp_item_set
					
					print_deb " Item set is now: #{item_set.count} objects"
					
				end

				#print_deb item_set.inspect
				#print_deb item_set.each { |item| puts item.inspect }

				###
				##	Filter items
				###

				item_set.each do |item|
					# Look through for the user-specified filters
					equal_conditions.each_pair do |method,value|
						# we should get an object by looking for the 
						# user-specified filter item (unless it doesn't
						# exist in the database...)
						db_object = eval("item.#{method}") # get the value we want to examine

						# handle the case when people are looking for nil-like values					
						if self.is_nil_like?(value)
							#print_deb "#{value} IS NIL-LIKE, checking for nil-like db object"
							# if they are searching for something akin to nil then
							# let's match if the db_object entry is akin to nil
							@working_set << item if self.is_nil_like?(db_object)
						elsif db_object.to_s == value
							# otherwise we do a normal comparison
							@working_set << item
						end
					end

					# Look for match conditions
					match_conditions.each_pair do |method,value|
						# we should get an object by looking for the 
						# user-specified filter item (unless it doesn't
						# exist in the database...)
						db_object = eval("item.#{method}") # get the value we want to examine
						
						# handle the case when people are looking for nil-like values
						# especially since doing a regex comparison on nil is kinda rough...				
						if is_nil_like?(value)
							# if they are searching for something akin to nil then
							# let's match if the db_object entry is akin to nil
							@working_set << item if self.is_nil_like?(db_object)
						elsif db_object.to_s =~ Regexp.new(value,true)
							# otherwise we do a normal regex comparison
							@working_set << item
						end
					end
				end
			end
			return @working_set
		end
	
		private
		
		# This method parses a string and returns the last collection
#		def  hlp_recursively_get_last_collection(item,method)
#			return items if method.split(".").count == 1
#		end

		def show_all_sets
			print_deb "Showing all Sets:"
			
			if @working_set
				class_name = get_type(@working_set.first)
				print_line "[Working Set]: #{@working_set.count} items of type #{class_name}"
			end
			
			@sets.each do |name,value| 
				class_name = get_type(value.first)
				print_line "[#{name}]: #{value.count} items of type #{class_name}"
			end	
		end
		
		def hlp_print_set(set=[], header="Working Set", class_name=nil)
			indent = '    '
			
			# TODO - this currently only supports homogeneous sets, maybe allow class_name="Mixed" ?
			class_name = get_type(set.first) unless class_name
			
			print_deb "Getting columns for #{class_name}"
			
			calculated_columns = get_columns(class_name)

			print_deb "header => #{header.to_s}"
			print_deb "columns => #{calculated_columns.to_s}"
			print_deb "set.length => #{set.length}"
			
			# generate a rex table
			tbl = Rex::Ui::Text::Table.new(
				'Header'  => header,
				'Indent'  => indent.length,
				'Columns' => calculated_columns
			)

			# display each item, reflecting on the column names
			set.each do |item|
				tbl_row = []
				calculated_columns.each do |column|
					data = eval("item.#{column}") 
					if data
						tbl_row << data
					else
						tbl_row << "nil"
					end
				end
				tbl << tbl_row
			end
			
			# print the bastard
			print_line tbl.to_s
		end
    		    		
    		# TODO - I'm sure there's a better way to do this... 
    		def get_type(item)
    			return item.class.name.split(":").last
    		end
    		
    		# This function calculates the fields we'll display for each type
    		# There's some reflection magic in here in case we don't want to manually
    		# specify which items we care about
    		def get_columns(class_name)
    			columns = []
			global_add = ['id']
    			global_remove = ['created_at', 'updated_at', 'datastore']
	
			if class_name == "Host"
				columns = [ 'address','name','state','os_name','os_flavor']
			elsif class_name == "Service"
				columns = ['port','proto','state','name']
			elsif class_name == "Session"
				columns = [ 'host_id', 'local_id', 'stype', 'closed_at', 'port', 'desc' ]
			else
				## generate the columns
				columns = []
				if Msf::DBManager.respond_to?("#{class_name}.columns")
	 				eval("Msf::DBManager::#{class_name}.columns.each {|type_col| columns << type_col.name }")
	 			else
	 				print_error("The database does not recognize #{class_name} objects")
	 				print_deb("Msf::DBManager didn't respond_to? #{class_name}.columns")
	 				return []
	 			end
			end		

			# Globally remove these    			
			columns = columns - global_remove

			# Globally add these
			columns =  global_add | columns

    			return columns
    		end
    		
    		
    		##
		## Commands for help
		##
		
		def longest_cmd_size
  			commands.keys.map {|x| x.size}.sort.last
		end

		# No extended help yet, but this is where more detailed documentation
		# on particular commands would live. Key is command, (not cmd_command),
		# value is the documentation.
		def extended_help
			{
				"fun_fake_cmd" =>              "This is a fake command. It's got its own special docs." +
					      (" " * longest_cmd_size) + "It might be long so so deal with formatting somehow."
			}
		end

		# Map for usages
		def fun_usage
			caller[0][/`cmd_(.*)'/]
			cmd = $1
			if extended_help[cmd] || commands[cmd]
				cmd_fun_help cmd
			else	# Called without arguments 
				commands.each_pair {|k,v| print_line "%-#{longest_cmd_size}s - %s" % [k,v] }
			end
		end

		def cmd_fun_help(*args)
			if args.empty?
				commands.each_pair {|k,v| print_line "%-#{longest_cmd_size}s - %s" % [k,v] }

				print_line 
				print_line "Make sure you've first configured & connected to database with db_connect..."
				print_line
			else
				args.each do |c|
					if extended_help[c] || commands[c]
						print_line "%-#{longest_cmd_size}s - %s" % [c,extended_help[c] || commands[c]]
					else
						print_error "Unknown command '#{c}'"
					end
				end
			end
		end
    
		
	end
	
	#
	# The constructor is called when an instance of the plugin is created.  The
	# framework instance that the plugin is being associated with is passed in
	# the framework parameter.  Plugins should call the parent constructor when
	# inheriting from Msf::Plugin to ensure that the framework attribute on
	# their instance gets set.
	#
	def initialize(framework, opts)
		# Return immediately if we don't have access to the DB
		super

		# Raise an error if we don't have a db
		raise "no db!" unless framework.db.active 	

		## Register the commands above
		console_dispatcher = add_console_dispatcher(DbFunCommandDispatcher)
	end


	#
	# The cleanup routine for plugins gives them a chance to undo any actions
	# they may have done to the framework.  For instance, if a console
	# dispatcher was added, then it should be removed in the cleanup routine.
	#
	def cleanup
		# If we had previously registered a console dispatcher with the console,
		# deregister it now.
		remove_console_dispatcher('DbFun')
	end

	#
	# This method returns a short, friendly name for the plugin.
	#
	def name
		"db_fun"
	end

	#
	# This method returns a brief description of the plugin.  It should be no
	# more than 60 characters, but there are no hard limits.
	#
	def desc
		"Adds a db-centric interface to metasploit"
	end
	
end ## End Class
end ## End Module
