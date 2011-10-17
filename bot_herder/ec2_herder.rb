# $Id: sample.rb 9212 2010-05-03 17:13:09Z jduck $
#

$:.unshift(File.join(File.expand_path(File.dirname(__FILE__)), '..', 'lib', 'lab'))

require 'bot_herder'
require 'vm_controller'
require 'bot'
require 'net/ssh'
require 'net/scp'


module Msf

###
#
# This class does basic ec2 instance herding.
#
###
class Plugin::Ec2Herder < Msf::Plugin
 ###
 #
 # This class implements a console command dispatcher.
 #
 ###
 class ConsoleCommandDispatcher
  include Msf::Ui::Console::CommandDispatcher

  attr_writer :herder

    def initialize(driver)
	super(driver)
	@herder = nil
	@bots = []
    end

  #
  # The dispatcher's name.
  #
  def name
   "EC2_Herder"
  end

  #
  # Returns the hash of commands supported by this dispatcher.
  #
  def commands
   {
    "herder_create" => "Create N instances in the EC2 cloud.",
    "herder_run_all" => "Run a command on every instance",
    "herder_run" => "Run a command on one instance",
    "herder_list_instances" => "List Current instances",
    "herder_set_group" => "Assign a group to an instance",
    "herder_update" => "Update all of the bots"
   }
  end

  #
  # This method handles the creation of botss.
  #
  def cmd_herder_create(*args)
    (1..Integer(args[0])).each do |i|
      bot = Bot.new({ 'vmid'=> "ec2_bot_#{i}", "driver" => "ec2"})
      @bots << bot
      bot.start
    end

  end
  
  def cmd_herder_run_all(*args)
    command = args[0]
    @herder.run_command_all(command)
  end
  
  def cmd_herder_run(*args) 
    @herder.run_command(args[0],args[1]) #(command, ip)  
  end

  def cmd_herder_run_group(*args) #(group, command)
    @bots.each{|bot|
	if(bot.group = args[0])
	    @herder.run_command(args[1],bot.ip)
	end
    }
  end
  
  def cmd_herder_list_instances(*args)
      print_status("Current Instances: #{@bots.size}")
	print_line("== Name \t IP \t Group")
      @bots.each{|bot|
	print_line("== #{bot.vmid} \t #{bot.ip} \t #{bot.group}")
      }    
  end

  def cmd_herder_set_group(*args)
     puts "Modifying #{args[0]} bots to group #{args[1]}"
     total = Integer(args[0])
     @bots.each{|bot|
	  if (bot.group == nil and total != 0)
	    bot.group = args[1]
	    total = total - 1 
	  end
	}
  end
  
  def cmd_herder_update()
      @bots = @herder.update()
      print_status("Current Number : #{@bots.size}")
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
  super

  # If this plugin is being loaded in the context of a console application
  # that uses the framework's console user interface driver, register
  # console dispatcher commands.
  console_dispatcher = add_console_dispatcher(ConsoleCommandDispatcher)
  @herder = ::BotHerder.new({"driver" => "ec2", "vmid" => "master"}) 

  ## Share the vms
  console_dispatcher.herder = @herder

  print_status("Creating the new EC2 herder..")

    #print_status("Updating the herder with current instances")
    #@bots = @herder.update()

 end

 #
 # The cleanup routine for plugins gives them a chance to undo any actions
 # they may have done to the framework.  For instance, if a console
 # dispatcher was added, then it should be removed in the cleanup routine.
 #
 def cleanup
  # If we had previously registered a console dispatcher with the console,
  # deregister it now.
  remove_console_dispatcher('Sample')
 end

 #
 # This method returns a short, friendly name for the plugin.
 #
 def name
  "EC2 Herder"
 end

 #
 # This method returns a brief description of the plugin.  It should be no
 # more than 60 characters, but there are no hard limits.
 #
 def desc
  "This plugin creates the EC2Herder and then allows you to 
  administer the instances."
 end

protected
end

end