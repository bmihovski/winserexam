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
ReDirUsr "OU=Lab Users,DC=WSA,DC=LAB"
#Create OU Lab Computers and then create two nested OUs - IT and Finance
New-ADOrganizationalUnit -Name "Lab Computers"
New-ADOrganizationalUnit -Name "IT" -Path "ou=Lab Computers,dc=wsa,dc=lab"
New-ADOrganizationalUnit -Name "Finance" -Path "ou=Lab Computers,dc=wsa,dc=lab"
#Change the default container for new computers to Lab Computers.
#All computers created or joined during the exam should be children of this OU
redircmp "OU=Lab Computers,DC=WSA,DC=LAB"
#Create new user Ivan Petkov in IT OU with account name ivan.petkov
New-ADUser -Name Ivan -SamAccountName ivan.petkov -GivenName Ivan -Surname Petkov `
-AccountPassword (ConvertTo-SecureString -AsPlainText Password1 -Force) `
-UserPrincipalName ivan.petkov@wsa.lab `
-Path "OU=IT,OU=Lab Users,DC=WSA,DC=LAB" `
-Enabled $true
#Create new user Mariana Parusheva in Finance OU with account name mariana.parusheva 
New-ADUser -Name Mariana -SamAccountName mariana.parusheva -GivenName Mariana -Surname Parusheva `
-AccountPassword (ConvertTo-SecureString -AsPlainText Password1 -Force) `
-UserPrincipalName mariana.parusheva@wsa.lab `
-Path "OU=Finance,OU=Lab Users,DC=WSA,DC=LAB" `
-Enabled $true
#Create new OU Lab Groups which will contain all security groups created during the exam
New-ADOrganizationalUnit -Name "Lab Groups"
#Create new global security group GS IT and add user Ivan as a member
New-ADGroup -Name 'GS IT' -Description 'members users in IT OU' -GroupCategory Security -GroupScope DomainLocal -SamAccountName 'GS IT' `
-Path "OU=Lab Groups,DC=WSA,DC=LAB"
Add-ADGroupMember -Identity 'GS IT' -Members ivan.petkov
Get-ADGroup -Identity 'GS IT'
#Create new global security group GS Finance and add userd Mariana as a member
New-ADGroup -Name 'GS Finance' -Description 'members users in Finance OU' -GroupCategory Security `
-GroupScope DomainLocal -SamAccountName 'GS Finance' `
-Path "OU=Lab Groups,DC=WSA,DC=LAB"
Add-ADGroupMember -Identity 'GS Finance' -Members mariana.parusheva
#Create new global security group GS Servers and add computer SLAVE as a member
New-ADGroup -Name 'GS Servers' -Description 'members computers in IT OU' -GroupCategory Security `
-GroupScope DomainLocal -SamAccountName 'GS Servers' `
-Path "OU=Lab Groups,DC=WSA,DC=LAB"
Add-ADGroupMember -Identity 'GS Servers' -Members "SLAVE$"
#On SLAVE install IIS role 
#On SLAVE create second site that will be listening on port 8000.
#For the site use the files provided as a link in the beginning of the document 
#On SLAVE, install File Server role if needed, so you can create and manage file shares.
#Then create folder C:\Common and share it as Common with both Share and NTFS permissions set to Full for Everyone 
#Create folder C:\Common\IT and set NTFS permissions to Full for GS IT and deny access for GS Finance 
#Create folder C:\Common\Finance and set NTFS permissions to Full for GS Finance and deny access for GS IT
# SLAVE
Enter-PSSession -ComputerName slave
Add-WindowsFeature Web-Server -IncludeManagementTools
Get-Service | Where -Property DisplayName -Like *Web*
#On SLAVE create second site that will be listening on port 8000.

C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -noexit -command "import-module webadministration | out-null"
set-executionpolicy unrestricted
New-Item iis:\Sites\ExamSite -bindings @{protocol="http";bindingInformation=":8000:ExamSite"} -physicalPath C:\Web-Site
#On SLAVE, install File Server role if needed, so you can create and manage file shares.
Install-WindowsFeature FS-FileServer,FS-Resource-Manager -IncludeManagementTools
#Then create folder C:\Common and share it as Common with both Share and NTFS permissions set to Full for Everyone
mkdir C:\Common
New-SmbShare -Name Common -Path C:\Common -FullAccess Everyone
[system.enum]::getnames([System.Security.AccessControl.FileSystemRights])
$acl = Get-Acl C:\Common
$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone","FullControl","Allow")
$acl.SetAccessRule($AccessRule)
$acl | Set-Acl C:\Common
Get-Acl C:\Common | fl
#Create folder C:\Common\IT and set NTFS permissions to Full for GS IT and deny access for GS Finance 
mkdir C:\Common\IT
$acl = Get-Acl C:\Common\IT
$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("WSA\GS IT","FullControl","Allow")
$acl.SetAccessRule($AccessRule)
$acl | Set-Acl C:\Common\IT
Get-Acl C:\Common\IT | fl

#Create GPO-Remote that enables remote management (windows service and firewall rule(s))
#Create GPO-IIS that enables port 8000/tcp and make it applicable only to SLAVE
#Create GPO-Drive that maps \\SLAVE\Common as local drive Z: 
#Create GPO-Wallpaper that changes the wallpaper with the one provided in the beginning of the document (first it must be placed on a shared resource)
# Go to Computer Configuration > Policies > Administrative Templates > Windows Components >
#Windows Remote Management (WinRM) > WinRM Service > Allow remote server management through WinRM.
# Go to Computer Configuration > Policies > Preferences > Control Panel Settings.
#And right-click Services and choose New > Service.
# Choose Automatic (Delayed Start) as startup type, pick WinRM as the service name, set Start service as the action.
# Go to Computer Configuration\Policies\Administrative Templates\Network\Network Connections\Windows Firewall\Domain Profile
#and set Windows Firewall: Protect all network connections to Enabled
# Go to Computer Configuration\Policies\Windows Settings\Security Settings\Windows Firewall
#with Advanced Security\Inbound Rules enable predefined rules Windows Remote Management WRM
# To reduce the exposure to this service we can remove the Private and only leave only Domain profile in place.
#Double-click the new rule we just created, go to Advanced tab and uncheck the Private option from the Profiles section.

#Create GPO-IIS that enables port 8000/tcp and make it applicable only to SLAVE
# Add custom inbound rule protocol and ports icmpv4 and profile domain

#Create GPO-Drive that maps \\SLAVE\Common as local drive Z: 
# Add new policy object MountSales with action create and change targeting from common and connect it to OU and tick reconnect

#Create GPO-Wallpaper that changes the wallpaper with the one provided in the beginning of the document
#(first it must be placed on a shared resource)

#Create PowerShell script named C:\Scripts\Track-Resources.ps1 that extracts available memory
#and free disk space counters and appends the results to the C:\Temp\Resources.log file.
#Data should be formatted like TIMESTAMP / TYPE : VALUE where TYPE is either RAM or HDD, and TIMESTAMP and VALUE are the ones coming from the corresponding counter
#Create a new schedule Track-Resources for the script and set it to execute every 5 minutes
$action = New-ScheduledTaskAction -Execute C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -Argument C:\Scripts\Track-Resources.ps1
$interval = (New-TimeSpan -Minutes 5)
$dt= ([DateTime]::Now)
$duration = $dt.AddYears(25) -$dt;
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).Date -RepetitionInterval $interval -RepetitionDuration $duration 
$task = New-ScheduledTask -Action $action -Trigger $trigger
Register-ScheduledTask -TaskName Track-Resources -InputObject $task