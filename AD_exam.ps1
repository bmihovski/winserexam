#Deploy one virtual machine and name it MASTER
#On MASTER set the external network to be with dynamic address and name it NIC-EXT 
#On MASTER set the internal network with address 192.168.240.1/24 and name it NIC-INT 
#On MASTER install and configure DHCP role to listen on NIC-INT and with pool starting from 192.168.240.100 to 192.168.240.200 named Lab Pool
#On MASTER install Active Directory DS role and configure the server to be a domain controller for WSA.LAB domain 
#On MASTER install and configure DNS feature for correct forward lookup zone 
#Deploy second virtual machine, name it SLAVE, and join it to the domain