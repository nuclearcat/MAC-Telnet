MAC-Telnet / MAC SSH for Linux
==============================

Based on [MAC-Telnet](https://github.com/haakonnessjoen/MAC-Telnet) 
the original work of 
[haakonnessjoen](https://github.com/haakonnessjoen) (_Håkon Nessjøen_).
The original version implements the following:

* A linux console tool for connecting to _MikroTik RouterOS_ devices via their
ethernet address.
* Linux daemon that implements the _MAC Telnet_ Daemon to permit connecting
to Linux machines via their ethernet address.

Forked to implement additional functionality for tunneling any TCP connection 
trough the through the _MAC Telnet_ protocol. The main use case is connecting to 
Linux machines via their ethernet address using _SSH_ protocol for security.

The server supports two modes of operation:
* Standard MAC-Telnet Server Mode
* TCP Connection Forwarding Mode: Tunnels a TCP connection to a local port on 
the client to a specific local port on the server side through MAC-Telnet 
protocol. This mode of operation is used for forwarding SSH connections through 
the MAC-Telnet protocol.

The client supports three modes of operation:
* Standard MAC-Telnet Client Mode
* TCP Connection Forwarding Mode: Tunnels a specific local port on the client to 
the serverthrough MAC-Telnet protocol.
* SSH Forwarding Mode: The client takes care of setting up the tunnel and 
launching the SSH client. 

The _MAC-Telnet_ and _Forwarding_ modes of operation are _not_ compatible. Both 
the client and the server must operate in the same mode for successful 
communications. 

The _SSH Forwarding Mode_ has the following advantages in comparison to standard
_MAC-Telnet_:

* The_mactelnet.users_ configuration file is not needed. Instead of maintaining 
another set of user passwords for _MAC-Telnet_, the standard authentication 
mechanisms supported by ssh are used.
* Public key authentication works seamlessly permiting logins without password.
* The communication between client and server is encrypyted by _SSH_.


Some use cases are as follows:

* In embedded systems it can be used for initial provisioning and for 
maintenance purposes in situations where a valid IP configuration is not 
available. Might be a useful addition to the rescue mode especially of embedded
systems without screens; connecting  using MAC-Telnet / MAC-SSH is much more 
convenient then fetching and connecting a serial cable.
* In datacentres it can be used for initial provisioning of physical and virtual
servers and might serve as a rescue system, when the IP configuration of any 
server gets messed up for any reason.


Installation
------------

Clone repository.

Then:
    make all install

Now you're ready.


Usage
-----

###mactelnet###

	$ mactelnet -h
	
	Usage: ./mactelnet <MAC|identity> [-v] [-h] [-q] [-n] [-l] [-S] [-P port]
           [-t <timeout>] [-u <username>] [-p <password>]

	Parameters:
	  MAC       MAC-Address of the RouterOS/mactelnetd device. Use mndp to 
	            discover it.
	  identity  The identity/name of your destination device. Uses MNDP protocol 
	            to find it.
	  -l        List/Search for routers nearby. (using MNDP)
	  -n        Do not use broadcast packets. Less insecure but requires root 
	            privileges.
	  -t        Amount of seconds to wait for a response on each interface.
	  -u        Specify username on command line.
	  -p        Specify password on command line.
	  -S        Use MAC-SSH instead of MAC-Telnet. (Implies -F)
	            Forward SSH connection through MAC-Telnet and launch SSH client.
	  -F        Forward connection through of MAC-Telnet without launching the 
	            SSH Client.
	  -P port   Local TCP port for forwarding SSH connection.
	            (If not specified, port 2222 by default.)
	  -q        Quiet mode.
	  -v        Print version and exit.
	  -h        Print help and exit.


### mactelnetd ###

	$ mactelnetd -h
	
Usage: ./mactelnetd [-v] [-h] [-S] [-P port] [-n] [-f]

	Parameters:
	  -f        Run process in foreground.
	  -n        Do not use broadcast packets. Just a tad less insecure.
	  -S / -F   Tunneling of TCP connections through  MAC-Telnet protocol,
	            instead of standard MAC-Telnet use.
	  -P        Local TCP port for SSH Daemon.
	            (If not specified, port 22 by default.)
	  -v        Print version and exit.
	  -h        Print help and exit.


### macping ###

	$ macping -h
	
	Usage: ./macping <MAC> [-h] [-f] [-c <count>] [-s <packet size>]
	
	Parameters:
	  MAC       MAC-Address of the RouterOS/mactelnetd device.
	  -f        Fast mode, do not wait before sending next ping request.
	  -s        Specify size of ping packet.
	  -c        Number of packets to send. (0 = unlimited)
	  -h        This help.


### mndp ###

$ mndp