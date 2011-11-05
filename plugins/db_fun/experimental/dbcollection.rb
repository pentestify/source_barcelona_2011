module Msf
class DBManager

class Collection < ActiveRecord::Base
	include DBSave

	# need to grok how all this stuff works
	
	belongs_to :workspace
	has_and_belongs_to_many :tags, :join_table => :hosts_tags
	has_many :services, :dependent => :destroy
	has_many :clients,  :dependent => :destroy
	has_many :vulns,    :dependent => :destroy
	has_many :notes,    :dependent => :destroy
	has_many :loots,    :dependent => :destroy, :order => "loots.created_at desc"
	has_many :sessions, :dependent => :destroy, :order => "sessions.opened_at"

	has_many :service_notes, :through => :services
	has_many :web_sites, :through => :services
	has_many :creds,    :through   => :services
	has_many :exploited_hosts, :dependent => :destroy

	validates_exclusion_of :address, :in => ['127.0.0.1']
	validates_uniqueness_of :address, :scope => :workspace_id

    def attribute_locked?(attr)
      n = notes.find_by_ntype("host.updated.#{attr}")
	  n && n.data[:locked]
    end
    
	# Returns the records in this collection
	attr_accessor :records
	
	# Returns the workspace to which this collection is assocated
	attr_accessor :my_workspace # this ain't right 
    
	#attr_accessor :id,:records
	#def initialize(id,records=[])
		#@id = id
		#	@records = records
	#end
			
	#def self.valid_set_id?(id)
		#true
		# see if any objects of type DbFunSet have matching id
	#end

protected



end # end DBManager class
end # end Msf Module

