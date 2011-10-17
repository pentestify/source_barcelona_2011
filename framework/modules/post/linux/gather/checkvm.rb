# $Id: checkvm.rb 13173 2011-07-14 19:43:09Z egypt $
##

##
# ## This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'rex'
require 'msf/core/post/common'
require 'msf/core/post/file'
require 'msf/core/post/linux/priv'
require 'msf/core/post/linux/system'

class Metasploit3 < Msf::Post

	include Msf::Post::Common
	include Msf::Post::File
	include Msf::Post::Linux::Priv
	include Msf::Post::Linux::System


	def initialize(info={})
		super( update_info( info,
				'Name'          => 'Linux Gather Virtual Environment Detection',
				'Description'   => %q{
					This module attempts to determine whether the system is running
					inside of a virtual environment and if so, which one. This
					module supports detectoin of Hyper-V, VMWare, VirtualBox, Xen,
					and QEMU/KVM.},
				'License'       => MSF_LICENSE,
				'Author'        => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>'],
				'Version'       => '$Revision: 13173 $',
				'Platform'      => [ 'linux' ],
				'SessionTypes'  => [ 'shell', 'meterpreter' ]
			))
	end

	# Run Method for when run command is issued
	def run
		print_status("Gathering System info ....")
		vm = nil
		dmi_info = nil

		if is_root?
			dmi_info = cmd_exec("/usr/sbin/dmidecode")
		end

		# Check DMi Info
		if dmi_info
			case dmi_info
			when /microsoft corporation/i
				vm = "MS Hyper-V"
			when /vmware/i
				vm = "VMware"
			when /virtualbox/i
				vm = "VirtualBox"
			when /qemu/i
				vm = "Qemu/KVM"
			when /domu/i
				vm = "Xen"
			end
		end

		# Check Modules
		if not vm
			loaded_modules = cmd_exec("/sbin/lsmod")
			case loaded_modules.gsub("\n", " ")
			when /vboxsf|vboxguest/i
				vm = "VirtualBox"
			when /vmw_ballon|vmxnet|vmw/i
				vm = "VMware"
			when /xen-vbd|xen-vnif/
				vm = "Xen"
			when /virtio_pci|virtio_net/
				vm = "Qemu/KVM"
			when /hv_vmbus|hv_blkvsc|hv_netvsc|hv_utils|hv_storvsc/
				vm = "MS Hyper-V"
			end
		end

		# Check SCSI Driver
		if not vm
			proc_scsi = read_file("/proc/scsi/scsi") rescue ""
			case proc_scsi.gsub("\n", " ")
			when /vmware/i
				vm = "VMware"
			when /vbox/
				vm = "VirtualBox"
			end
		end

		# Check IDE Devices
		if not vm
			case cmd_exec("cat /proc/ide/hd*/model")
			when /vbox/i
				vm = "VirtualBox"
			when /vmware/i
				vm = "VMware"
			when /qemu/i
				vm = "Qemu/KVM"
			when /virtual (hd|cd)/i
				vm = "Hyper-V/Virtual PC"
			end
		end

		# Check using lspci
		if not vm
			case get_sysinfo[:distro]
			when /oralce|centos|suse|redhat|mandrake|slackware|fedora/
				lspci_data = cmd_exec("/sbin/lspci")
			when /debian|ubuntu/
				lspci_data = cmd_exec("/usr/bin/lspci")
			else
				lspci_data = cmd_exec("lspci")
			end

			case lspci_data.gsub("\n", " ")
			when /vmware/i
				vm = "VMware"
			when /virtualbox/i
				vm = "VirtualBox"
			end
		end

		# Xen bus check
		if not vm
			if cmd_exec("ls -1 /sys/bus").split("\n").include?("xen")
				vm = "Xen"
			end
		end

		# Check using lscpu
		if not vm
			case cmd_exec("lscpu")
			when /Xen/
				vm = "Xen"
			when /KVM/
				vm = "KVM"
			when /Microsoft/
				vm = "MS Hyper-V"
			end
		end

		# Check dmesg Output
		if not vm
			dmesg = cmd_exec("dmesg")
			case dmesg
			when /vboxbios|vboxcput|vboxfacp|vboxxsdt|(vbox cd-rom)|(vbox harddisk)/i
				vm = "VirtualBox"
			when /(vmware virtual ide)|(vmware pvscsi)|(vmware virtual platform)/i
				vm = "VMware"
			when /(xen_mem)|(xen-vbd)/i
				vm =  "Xen"
			when /(qemu virtual cpu version)/i
				vm = "Qemu/KVM"
			when %r{/dev/vmnet}
				print_good("This appears to be a VMware %bldHost%clr")
			end
		end

		if vm
			print_good("This appears to be a #{vm} Virtual Machine")
		else
			print_status("This appears to be a Physical Machine")
		end

	end



end
