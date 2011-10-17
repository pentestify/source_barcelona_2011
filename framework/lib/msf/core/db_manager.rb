require 'msf/core'
require 'msf/core/db'
require 'msf/core/task_manager'

module Msf

###
#
# The db module provides persistent storage and events. This class should be instantiated LAST
# as the active_suppport library overrides Kernel.require, slowing down all future code loads.
#
###

class DBManager

	# Provides :framework and other accessors
	include Framework::Offspring

	# Returns true if we are ready to load/store data
	def active
		return false if not @usable
		(ActiveRecord::Base.connected? && ActiveRecord::Base.connection.active? && migrated) rescue false
	end

	# Returns true if the prerequisites have been installed
	attr_accessor :usable

	# Returns the list of usable database drivers
	attr_accessor :drivers

	# Returns the active driver
	attr_accessor :driver

	# Stores the error message for why the db was not loaded
	attr_accessor :error

	# Stores a TaskManager for serializing database events
	attr_accessor :sink
	
	# Flag to indicate database migration has completed
	attr_accessor :migrated

	def initialize(framework, opts = {})

		self.framework = framework
		self.migrated  = false
		@usable = false

		# Don't load the database if the user said they didn't need it.
		if (opts['DisableDatabase'])
			self.error = "disabled"
			return
		end

		initialize_database_support
	end

	#
	# Do what is necessary to load our database support
	#
	def initialize_database_support

		# Load ActiveRecord if it is available
		begin
			require 'rubygems'
			require 'active_record'
			require 'msf/core/db_objects'
			require 'msf/core/model'

			# Database drivers can reset our KCODE, do not let them
			$KCODE = 'NONE' if RUBY_VERSION =~ /^1\.8\./

			@usable = true

		rescue ::Exception => e
			self.error = e
			elog("DB is not enabled due to load error: #{e}")
			return false
		end

		#
		# Determine what drivers are available
		#
		initialize_drivers

		#
		# Instantiate the database sink
		#
		initialize_sink

		true
	end

	#
	# Scan through available drivers
	#
	def initialize_drivers
		self.drivers = []
		tdrivers = %W{ postgresql }
		tdrivers.each do |driver|
			begin
				ActiveRecord::Base.default_timezone = :utc
				ActiveRecord::Base.establish_connection(:adapter => driver)
				if(self.respond_to?("driver_check_#{driver}"))
					self.send("driver_check_#{driver}")
				end
				ActiveRecord::Base.remove_connection
				self.drivers << driver
			rescue ::Exception
			end
		end

		if(not self.drivers.empty?)
			self.driver = self.drivers[0]
		end

		# Database drivers can reset our KCODE, do not let them
		$KCODE = 'NONE' if RUBY_VERSION =~ /^1\.8\./
	end

	#
	# Create a new database sink and initialize it
	#
	def initialize_sink
		self.sink = TaskManager.new(framework)
		self.sink.start
	end

	#
	# Add a new task to the sink
	#
	def queue(proc)
		self.sink.queue_proc(proc)
	end

	#
	# Connects this instance to a database
	#
	def connect(opts={})

		return false if not @usable

		nopts = opts.dup
		if (nopts['port'])
			nopts['port'] = nopts['port'].to_i
		end

		nopts['pool'] = 75

		begin
			self.migrated = false
			create_db(nopts)

			# Configure the database adapter
			ActiveRecord::Base.establish_connection(nopts)

			# Migrate the database, if needed
			migrate

			# Set the default workspace
			framework.db.workspace = framework.db.default_workspace
			
			# Flag that migration has completed
			self.migrated = true
		rescue ::Exception => e
			self.error = e
			elog("DB.connect threw an exception: #{e}")
			dlog("Call stack: #{$@.join"\n"}", LEV_1)
			return false
		ensure
			# Database drivers can reset our KCODE, do not let them
			$KCODE = 'NONE' if RUBY_VERSION =~ /^1\.8\./
		end

		true
	end

	#
	# Attempt to create the database
	#
	# If the database already exists this will fail and we will continue on our
	# merry way, connecting anyway.  If it doesn't, we try to create it.  If
	# that fails, then it wasn't meant to be and the connect will raise a
	# useful exception so the user won't be in the dark; no need to raise
	# anything at all here.
	#
	def create_db(opts)
		begin
			case opts["adapter"]
			when 'postgresql'
				# Try to force a connection to be made to the database, if it succeeds
				# then we know we don't need to create it :)
				ActiveRecord::Base.establish_connection(opts)
				conn = ActiveRecord::Base.connection
			end
		rescue ::Exception => e
			errstr = e.to_s
			if errstr =~ /does not exist/i or errstr =~ /Unknown database/
				ilog("Database doesn't exist \"#{opts['database']}\", attempting to create it.")
				ActiveRecord::Base.establish_connection(opts.merge('database' => nil))
				ActiveRecord::Base.connection.create_database(opts['database'])
			else
				ilog("Trying to continue despite failed database creation: #{e}")
			end
		end
		ActiveRecord::Base.remove_connection
	end

	#
	# Disconnects a database session
	#
	def disconnect
		begin
			ActiveRecord::Base.remove_connection
		rescue ::Exception => e
			self.error = e
			elog("DB.disconnect threw an exception: #{e}")
		ensure
			# Database drivers can reset our KCODE, do not let them
			$KCODE = 'NONE' if RUBY_VERSION =~ /^1\.8\./
		end
	end

	#
	# Migrate database to latest schema version
	#
	def migrate(verbose=false)
		begin
			migrate_dir = ::File.join(Msf::Config.install_root, "data", "sql", "migrate")
			ActiveRecord::Migration.verbose = verbose
			ActiveRecord::Migrator.migrate(migrate_dir, nil)
		rescue ::Exception => e
			self.error = e
			elog("DB.migrate threw an exception: #{e}")
			dlog("Call stack:\n#{e.backtrace.join "\n"}")
			return false
		end
		return true
	end

	def workspace=(workspace)
		@workspace_name = workspace.name
	end

	def workspace
		framework.db.find_workspace(@workspace_name)
	end

end
end

