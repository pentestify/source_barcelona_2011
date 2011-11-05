		#TODO:  Turn a db_set into it's own class
		class DbFunSet < Array
			attr_accessor :id,:records
			def initialize(id,records=[])
				@id = id
				@records = records
			end
			
			def self.valid_set_id?(id)
				true
				# see if any objects of type DbFunSet have matching id
			end
		end
		# ^^^^ the stuff above isn't utilized yet, just musing here
