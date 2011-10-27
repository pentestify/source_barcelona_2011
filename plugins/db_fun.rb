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
		end
		
		# create instance method print_deb so we can turn it on and off w/o having to use lots of if stmts

		#class Msf::Plugin
		#	printdebug = self.instance_method(:print_deb)
		#	define_method(:print_deb) do
		#		printdebug.bind(self).call("[DEBUG] #{msg}") if @debug
		#	end
		#end
		
		def print_deb(msg='')
			print_good("[debug] #{msg}") if @debug
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
			"db_set_add_to" =>  "[id] - Add these items to the working set",
			"db_set_del_from" => "[id] - Delete these items to the working set",	
			"db_set_run_module" => "[id] module [payload] OPT=val - run modules against a set",
			"db_fun_show_examples" => "I'm confused, show me some examples",
			"db_set_auto" => "Automatically create some default sets like: windows,linux,all_hosts,etc"
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
							"db_search services where proto=tcp" ],
			"db_set_create" => "db_set_create 1  # creates db set with id 1 using latest query",
			"db_set_add_to" =>  "db_set_add_to 1  # adds to db set 1 using latest query results",
			"db_set_run_module" => "db_set_run_module 1 auxiliary/scanner/smb/smb_version"
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
			hlp_print_set result_set, "Searched Set" #, class_name
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
					print_deb "Module (#{modjool} is valid.)"
					# if this arg matches a known module, assume it's a module
					mod_args[:module] = modjool
					args.shift # this doesn't throw an error if args is empty
				# else
				#	raise ArgumentError.new ("The module (#{modjool} is not valid.)")
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

				print_deb("Module args: #{mod_args[:module]} #{mod_args[:payload]}, " +
							"and options: #{mod_opts.to_s}")
				self.run_module(fmwk,mod_args,mod_opts)
			else 
				print_error "Set some options chief!"
				return fun_usage
			end		
		end

		def cmd_db_set_create(*args)
			#TODO:  Find a way to persist sets by serializing? them to .msf4 etc
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
			#TODO:  Add set where hosts os_name is nil or unknown -- need to ask jcran how 2 do nil
			self.create_set("windows", "hosts where os_name~windows")
			self.create_set("linux", "hosts where os_name~linux")
			self.create_set("all_hosts", "hosts")
			#self.create_set("unknown","hosts where os_name=nil")
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
		
		def create_set(set_id,search_str)
			args = search_str.split(" ")
			self.dbsearch(args)
			self.cmd_db_set_create(set_id)
		end
		
		def normalize_module(m)
			# TODO:  Improve this ghetto crap
			# remove any leading slashes and any leading words like auxiliary or post etc
			modjool = m.downcase
			modjool.gsub!(/^[\\\/]+/,'') # this is supposed to get rid of leading slashes
			print_deb "modjool with leading slashes stripped: #{modjool}"
			modjool.gsub!(/^auxiliary|^encoders|^exploit[s]*|^nops|^payloads|^post/,'')
			modjool.gsub!(/^[\\\/]+/,'') # this is supposed to get rid of leading slashes
			print_deb "modjool with leading module types stripped: #{modjool}"
			modjool
		end
		
		#
		# This method actually runs a module against a set, meant to be called by db_set_run_module etc
		#
		def run_module(framework=nil,args={},opts={})
			# possible args - :set :module :payload
			# possible opts - :rhost :lhost :lport :rport etc
			#print_deb "The set is #{args[:set].to_s}"
			# TODO:  Merge in some good default option settings like VERBOSE => false etc
			print_deb "Running module with framework:#{framework} args:#{args} opts:#{opts}"
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
			modjool = self.normalize_module(args[:module])
			inst = get_instance(framework,modjool)
			unless inst
				raise ("Unable to create module instance, framework instance was #{framework}")
				#framework.cleanup
			end
			print_deb "Number of items in the set = #{args[:set].count}"
			if args[:set].count > 0
				args[:set].each do |item| 
					if item.class == Msf::DBManager::Host
						print_good "Running module #{modjool} against #{item.address}"
						#`
						# Do it like a boss d-_-b
						#
						# it's probably a good idea to consolidate RHOSTS at some point
						#  to avoid calling the same module repeatedly for each ip, instead of once
						#  for now let's just keep it simple
						opts[:RHOSTS.to_s] = item.address
						# for exploit:  opts[:RHOST] = item.address.to_s
						print_deb("Module args: #{modjool} #{args[:payload]}, " +
							"and options: #{opts.to_s}")
						begin
							case inst.type
							# TODO:  Validate options for the particular module
							# Fire it off.
								when /auxiliary/
									print_deb "Input is: #{inst.user_input}, Output is: #{inst.user_output}"
									inst.run_simple(
									'Payload'     => args[:payload],
									'Options'		=> opts,
									'LocalInput'	=> inst.user_input,
									'LocalOutput'	=> inst.user_output,
									#'LocalInput'	=> Rex::Ui::Text::Input::Buffer.new,
									#'LocalOutput'	=> Rex::Ui::Text::Output::Buffer.new,
									# Is there a way to make output be the console?
									#'RunAsJob'		=> true
									)
								when /post/
									# TODO:
								when /exploit/
									inst.exploit_simple(
									'Payload'     => args[:payload],
									'Options'		=> opts,
									'LocalInput'	=> Rex::Ui::Text::Input::Buffer.new,
									'LocalOutput'	=> Rex::Ui::Text::Output::Buffer.new,
									# Is there a way to make output be the console?
									#'RunAsJob'		=> true
									)
									session.load_stdapi
								else
									# WTFBBQ?
							# TODO:  check if most aux/post mods write to the db, otherwise report
							# aux.report_note({
							#				:data => "required" #whatever it is you're making a note of
							#				:type => "required" # type of note, e.g. smb_peer_os
							# 				:workspace => "optional" # workspace to associate w/note
							#				:host => item.address #IP address or Host obj to assoc.
							#				:service => "optional" #Service object to assoc.
							#				:port =>	"optional" #along with :host and proto, a
										# service to associate with this Note
							#				:proto => "optional" along with :host and port, a 
										# service to associate with this Note
							#				:update => what to do in case a similar Note exists
										# The +:update+ option can have the following values:
											#unique+::allow only a single Note per +:host+/+:type+ pair
											#:unique_data+::like +:uniqe+, but also compare +:data+
											#:insert+::always insert a new Note regardless
							#				})
							
							end # end case

						rescue Exception => e
							raise("Unable to run module #{modjool}, check required options\n" +
							"#{e.backtrace}")
						end
					else 
						print_error "#{item.class} is not a host!"
					end
				end
			else
				print_error "Nothing in the set!" 
			end
		end
		
		def get_instance(framework,modjool)
			working = ["auxiliary","exploits","payloads","post"]
			unsupported = ["encoders","nops"]
			nonsense = ["payloads"]
			working.each do |type|
				if framework.send(type).include?(modjool)
					# then this modjool is valid and of type type
					if nonsense.include?(modjool)
						# Then this don't make no damn sense
						raise ArgumentError.new ("It doesn't make sense to use #{modjool} as a module")
					else
						return framework.send(type).create(modjool)
					end
				end
			end
			# if that wasn't a good module, let's see if we can tell why
			unsupported.each do |type|
				if framework.send(type).include?(modjool)
					# Then we recognize your module but don't support it
					raise ArgumentError.new ("The module is valid but it's type (#{type}) is not supported")
				end
			end
			# otherwise this modjool just isn't recognized as a valid module
			raise ArgumentError.new ("#{modjool} is not a valid module")
		end # end method
		
		# perform the actual search and return the matching set
		def dbsearch (args=[])
			# Make sure we form the class name correctly
			class_name = args[0].downcase
			class_name[0] = class_name[0].capitalize
			class_name = class_name.singularize
						
			print_deb ("Class name: " + class_name)
			 
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
				
					print_line "parsing arg #{arg}"
				
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
						value = nil if value == "nil"
						db_object = eval("item.#{method}")

						# we should get an object by looking for the 
						# user-specified filter item (unless it doesn't
						# exist in the database...						
						if db_object.to_s == value
							@working_set << item
						end
					end

					# Look for match conditions
					match_conditions.each_pair do |method,value|
						db_object = eval("item.#{method}")
						if db_object.to_s =~ Regexp.new(value,true)
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
		
		def hlp_print_set(set=[], header="Working Set", class_name="Host")
			indent = '    '
			
			# TODO - this currently only support homogeneous sets
			class_name = get_type(set.first)
			
			
			print_deb "getting columns for #{class_name}"
			
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
    			global_remove = ['created_at', 'updated_at']
	
			if class_name == "Host"
				columns = [ 'address','name','state','os_name','os_flavor']
			elsif class_name == "Service"
				columns = ['port','proto','state','name']
			else
				## generate the columns
				columns = []
	 			eval("Msf::DBManager::#{class_name}.columns.each {|type_col| columns << type_col.name }")
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
