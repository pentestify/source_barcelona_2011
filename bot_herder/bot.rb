require 'vm'

class Bot < Lab::Vm  
    attr_accessor :group
    attr_accessor :ip

    def initialize(config)
        super(config)
    end
    
    def slow_http_post(target)
        puts "Initiating slow http post"
    end
    
end
