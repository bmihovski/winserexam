# git push --porcelain
#Deploy one virtual machine and name it MASTER
#On MASTER set the external network to be with dynamic address and name it NIC-EXT 
#On MASTER set the internal network with address 192.168.240.1/24 and name it NIC-INT 
#On MASTER install and configure DHCP role to listen on NIC-INT and with pool starting from 192.168.240.100
#to 192.168.240.200 named Lab Pool
#On MASTER install Active Directory DS role and configure the server to be a domain controller for WSA.LAB domain 
#On MASTER install and configure DNS feature for correct forward lookup zone 
#Deploy second virtual machine, name it SLAVE, and join it to the domain
Rename-Computer -NewName MASTER
Enable-PSRemoting
Get-NetAdapter
Rename-NetAdapter -Name ethernet -NewName NIC-EXT
Rename-NetAdapter -Name 'ethernet 2' -NewName NIC-INT
#On MASTER set the internal network with address 192.168.240.1/24 and name it NIC-INT
New-NetIPAddress -IPAddress 192.168.240.1 -PrefixLength 24 -InterfaceAlias nic-int
#On MASTER install and configure DHCP role to listen on NIC-INT and with pool starting from 192.168.240.100
#to 192.168.240.200 named Lab Pool
Install-WindowsFeature -Name DHCP -IncludeManagementTools
Add-DhcpServerSecurityGroup -computername master
Restart-Service -Name DHCPServer
Get-DhcpServerv4Binding
Set-DhcpServerv4Binding -InterfaceAlias nic-int -BindingState $true
Add-DhcpServerv4Scope -Name 'Lab Pool' -StartRange 192.168.240.100 -EndRange 192.168.240.200 -SubnetMask 255.255.255.0
Get-DhcpServerv4Binding
Set-DhcpServerv4OptionValue -OptionId 3 -Value 192.168.240.1
Set-DhcpServerv4OptionValue -OptionId 6 -Value 192.168.240.1 -Force
#On MASTER install Active Directory DS role and configure the server to be a domain controller for WSA.LAB domain 
Install-WindowsFeature -Name ad-domain-services -IncludeManagementTools
Import-Module ADDSDeployment
Install-ADDSForest `
-CreateDnsDelegation:$false `
-DatabasePath "C:\Windows\NTDS" `
-DomainMode "WinThreshold" `
-DomainName "WSA.LAB" `
-DomainNetbiosName "EXAM" `
-ForestMode "WinThreshold" `
-InstallDns:$true `
-LogPath "C:\Windows\NTDS" `
-NoRebootOnCompletion:$false `
-SysvolPath "C:\Windows\SYSVOL" `
-Force:$true
Add-DhcpServerInDC
#Deploy second virtual machine, name it SLAVE, and join it to the domain
New-ADComputer -Name SLAVE
#SLAVE
Rename-NetAdapter -Name ethernet -NewName internal
Rename-Computer -NewName SLAVE
Restart-Computer
Add-Computer -DomainName WSA.LAB -DomainCredential Administrator
#Master
Get-ADComputer slave
#Create OU Lab Users and then create two nested OUs - IT and Finance 
#Change the default container for new users to Lab Users. All users created during the exam, should be under this OU 
#Create OU Lab Computers and then create two nested OUs - IT and Finance
#Change the default container for new computers to Lab Computers.
#All computers created or joined during the exam should be children of this OU
#Create new user Ivan Petkov in IT OU with account name ivan.petkov 
#Create new user Mariana Parusheva in Finance OU with account name mariana.parusheva 
#Create new OU Lab Groups which will contain all security groups created during the exam 
#Create new global security group GS IT and add user Ivan as a member 
#Create new global security group GS Finance and add userd Mariana as a member 
#Create new global security group GS Servers and add computer SLAVE as a member
New-ADOrganizationalUnit -Name "Lab Users"
New-ADOrganizationalUnit -Name "IT" -Path "ou=Lab Users,dc=wsa,dc=lab"
New-ADOrganizationalUnit -Name "Finance" -Path "ou=Lab Users,dc=wsa,dc=lab"
#Change the default container for new users to Lab Users. All users created during the exam, should be under this OU
redircmp "OU=Lab Users,DC=WSA,DC=LAB"
 
