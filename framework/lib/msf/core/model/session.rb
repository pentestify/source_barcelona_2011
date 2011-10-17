module Msf
class DBManager

class Session < ActiveRecord::Base
	belongs_to :host

	has_one :workspace, :through => :host

	has_many :events, :class_name => "SessionEvent", :order => "created_at"
	has_many :routes

	named_scope :alive, :conditions => "closed_at IS NULL"
	named_scope :dead, :conditions => "closed_at IS NOT NULL"

	serialize :datastore
end

end
end
