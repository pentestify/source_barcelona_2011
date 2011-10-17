##
# $Id: checkvm.rb 12990 2011-06-21 00:38:04Z darkoperator $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'rex'
require 'msf/core/post/windows/registry'

class Metasploit3 < Msf::Post

	include Msf::Post::Windows::Registry

	def initialize(info={})
		super( update_info( info,
				'Name'          => 'Windows Gather Virtual Environment Detection',
				'Description'   => %q{
					This module attempts to determine whether the system is running
					inside of a virtual environment and if so, which one. This
					module supports detectoin of Hyper-V, VMWare, Virtual PC,
					VirtualBox, Xen, and QEMU.
					},
				'License'       => MSF_LICENSE,
				'Author'        => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>'],
				'Version'       => '$Revision: 12990 $',
				'Platform'      => [ 'windows' ],
				'SessionTypes'  => [ 'meterpreter' ]
			))
	end

	# Method for detecting if it is a Hyper-V VM
	def hypervchk(session)
		begin
			vm = false
			key = session.sys.registry.open_key(HKEY_LOCAL_MACHINE, 'SOFTWARE\Microsoft', KEY_READ)
			sfmsvals = key.enum_key
			if sfmsvals.include?("Hyper-V")
				vm = true
			elsif sfmsvals.include?("VirtualMachine")
				vm = true
			end
			key.close
		rescue
		end
		if not vm
			begin
				key = session.sys.registry.open_key(HKEY_LOCAL_MACHINE, 'SYSTEM\ControlSet001\Services', KEY_READ)
				srvvals = key.enum_key
				if srvvals.include?("vmicheartbeat")
					vm = true
				elsif srvvals.include?("vmicvss")
					vm = true
				elsif srvvals.include?("vmicshutdown")
					vm = true
				elsif srvvals.include?("vmicexchange")
					vm = true
				end
			rescue
			end
		end
		print_status("This is a Hyper-V Virtual Machine") if vm
		return vm
	end

	# Method for checking if it is a VMware VM
	def vmwarechk(session)
		vm = false
		begin
			key = session.sys.registry.open_key(HKEY_LOCAL_MACHINE, 'SYSTEM\ControlSet001\Services', KEY_READ)
			srvvals = key.enum_key
			if srvvals.include?("vmdebug")
				vm = true
			elsif srvvals.include?("vmmouse")
				vm = true
			elsif srvvals.include?("VMTools")
				vm = true
			elsif srvvals.include?("VMMEMCTL")
				vm = true
			end
			key.close
		rescue
		end
		if not vm
			begin
				key = session.sys.registry.open_key(HKEY_LOCAL_MACHINE, 'HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0')
				if key.query_value('Identifier').data.downcase =~ /vmware/
					vm = true
				end
			rescue
			end
			key.close
		end
		if not vm
			vmwareprocs = [
				"vmwareuser.exe",
				"vmwaretray.exe"
			]
			session.sys.process.get_processes().each do |x|
				vmwareprocs.each do |p|
					if p == (x['name'].downcase)
						vm = true
					end
				end
			end
		end
		print_status("This is a VMware Virtual Machine") if vm
		return vm

	end

	# Method for checking if it is a Virtual PC VM
	def checkvrtlpc(session)
		vm = false
		vpcprocs = [
			"vmusrvc.exe",
			"vmsrvc.exe"
		]
		session.sys.process.get_processes().each do |x|
			vpcprocs.each do |p|
				if p == (x['name'].downcase)
					vm = true
				end
			end
		end
		if not vm
			begin
				key = session.sys.registry.open_key(HKEY_LOCAL_MACHINE, 'SYSTEM\ControlSet001\Services', KEY_READ)
				srvvals = key.enum_key
				
				if srvvals.include?("vpc-s3")
					vm = true
				elsif srvvals.include?("vpcuhub")
					vm = true
				elsif srvvals.include?("msvmmouf")
					vm = true
				end
				key.close
			rescue
			end
		end
		print_status("This is a VirtualPC Virtual Machine") if vm
		return vm
	end

	# Method for checking if it is a VirtualBox VM
	def vboxchk(session)
		vm = false
		vboxprocs = [
			"vboxservice.exe",
			"vboxtray.exe"
		]
		session.sys.process.get_processes().each do |x|
			vboxprocs.each do |p|
				if p == (x['name'].downcase)
					vm = true
				end
			end
		end
		if not vm
			begin
				key = session.sys.registry.open_key(HKEY_LOCAL_MACHINE, 'HARDWARE\ACPI\DSDT', KEY_READ)
				srvvals = key.enum_key
				if srvvals.include?("VBOX__")
					vm = true
				end
			rescue
			end
		end
		if not vm
			begin
				key = session.sys.registry.open_key(HKEY_LOCAL_MACHINE, 'HARDWARE\ACPI\FADT', KEY_READ)
				srvvals = key.enum_key
				if srvvals.include?("VBOX__")
					vm = true
				end
			rescue
			end
		end
		if not vm
			begin
				key = session.sys.registry.open_key(HKEY_LOCAL_MACHINE, 'HARDWARE\ACPI\RSDT', KEY_READ)
				srvvals = key.enum_key
				if srvvals.include?("VBOX__")
					vm = true
				end
			rescue
			end
		end
		if not vm
			begin
				key = session.sys.registry.open_key(HKEY_LOCAL_MACHINE, 'HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0')
				if key.query_value('Identifier').data.downcase =~ /vbox/
					vm = true
				end
			rescue
			end
		end
		if not vm
			begin
				key = session.sys.registry.open_key(HKEY_LOCAL_MACHINE, 'HARDWARE\DESCRIPTION\System')
				if key.query_value('SystemBiosVersion').data.downcase =~ /vbox/
					vm = true
				end
			rescue
			end
		end
		if not vm
			begin
				key = session.sys.registry.open_key(HKEY_LOCAL_MACHINE, 'SYSTEM\ControlSet001\Services', KEY_READ)
				srvvals = key.enum_key
				if srvvals.include?("VBoxMouse")
					vm = true
				elsif srvvals.include?("VBoxGuest")
					vm = true
				elsif srvvals.include?("VBoxService")
					vm = true
				elsif srvvals.include?("VBoxSF")
					vm = true
				end
				key.close
			rescue
			end
		end
		print_status("This is a Sun VirtualBox Virtual Machine") if vm
		return vm
	end

	# Method for checking if it is a Xen VM
	def xenchk(session)
		vm = false
		xenprocs = [
			"xenservice.exe"
		]
		session.sys.process.get_processes().each do |x|
			xenprocs.each do |p|
				if p == (x['name'].downcase)
					vm = true
				end
			end
		end
		if not vm
			begin
				key = session.sys.registry.open_key(HKEY_LOCAL_MACHINE, 'HARDWARE\ACPI\DSDT', KEY_READ)
				srvvals = key.enum_key
				if srvvals.include?("Xen")
					vm = true
				end
			rescue
			end
		end
		if not vm
			begin
				key = session.sys.registry.open_key(HKEY_LOCAL_MACHINE, 'HARDWARE\ACPI\FADT', KEY_READ)
				srvvals = key.enum_key
				if srvvals.include?("Xen")
					vm = true
				end
			rescue
			end
		end
		if not vm
			begin
				key = session.sys.registry.open_key(HKEY_LOCAL_MACHINE, 'HARDWARE\ACPI\RSDT', KEY_READ)
				srvvals = key.enum_key
				if srvvals.include?("Xen")
					vm = true
				end
			rescue
			end
		end
		if not vm
			begin
				key = session.sys.registry.open_key(HKEY_LOCAL_MACHINE, 'SYSTEM\ControlSet001\Services', KEY_READ)
				srvvals = key.enum_key
				if srvvals.include?("xenevtchn")
					vm = true
				elsif srvvals.include?("xennet")
					vm = true
				elsif srvvals.include?("xennet6")
					vm = true
				elsif srvvals.include?("xensvc")
					vm = true
				elsif srvvals.include?("xenvdb")
					vm = true
				end
				key.close
			rescue
			end
		end
		print_status("This is a Xen Virtual Machine") if vm
		return vm
	end

	def qemuchk(session)
		vm = false
		if not vm
			begin
				key = session.sys.registry.open_key(HKEY_LOCAL_MACHINE, 'HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0')
				if key.query_value('Identifier').data.downcase =~ /qemu/
					print_status("This is a QEMU/KVM Virtual Machine")
					vm = true
				end
			rescue
			end
		end
		if not vm
			begin
				key = session.sys.registry.open_key(HKEY_LOCAL_MACHINE, 'HARDWARE\DESCRIPTION\System\CentralProcessor\0')
				if key.query_value('ProcessorNameString').data.downcase =~ /qemu/
					print_status("This is a QEMU/KVM Virtual Machine")
					vm = true
				end
			rescue
			end
		end

		return vm
	end

	# run Method
	def run
		print_status("Checking if #{sysinfo['Computer']} is a Virtual Machine .....")
		found = hypervchk(session)
		found = vmwarechk(session) if not found
		found = checkvrtlpc(session) if not found
		found = vboxchk(session) if not found
		found = xenchk(session) if not found
		found = qemuchk(session) if not found
		print_status("It appears to be physical host.") if not found
	end
end
