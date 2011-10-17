require 'vm'
require 'enumerator'
#this currently subclasses VM but probably doesn't need to

class BotHerder < Lab::Vm  

    include Enumerable
    
    def initialize(config=YAML::load_file("/home/willis/Desktop/whatever.yml"))
        super(config)
        @bots = []
        puts "\t <===> You have the power <===> \t"
    end
    
    def each &block
        @bots.each { |bot| yield bot }
    end
    
    def [](number)
        @bots[number]
    end
     
    def create(n)
        (1..Integer(n)).each do |i|
            bot = Bot.new({ 'vmid'=> "ec2_bot_#{i}", "driver" => "ec2"})
            @bots << bot
            bot.start
        end
    end

    def copy_file_all(user,file,dest)
        ips = list_ips()
        ips.each{|ip| scp_file(user,ip,file,dest)}
    end
    
    def run_command_all(command)
        ips = list_ips()
        ips.each{|ip| run_command(command,ip)}
    end
    
    def list_bots()
        ips = list_ips()
        ips.each{|ip| puts "ip\n"}        
    end
    
	
    def scp_file(user, ip, file, dest)
	Net::SCP.upload!(ip, user,
		file.to_s, dest)
    end
    
    def update
        ips = list_ips()
        i = 0
        ips.each{|ip|
            if (@bots[i] == nil)
                @bots[i] = Bot.new({ 'vmid'=> "ec2_bot_#{i}", "driver" => "ec2"})
                @bots[i].ip = ip
            else
                @bots[i].ip = ip
            end
            i = i + 1
        }
        return @bots
    end
    

end
