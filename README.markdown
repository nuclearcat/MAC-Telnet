MAC-Telnet / MAC SSH for Linux
==============================

Based on the original work of haakonnessjoen (Håkon Nessjøen) that implements
the following:

* A linux console tool for connecting to MikroTik RouterOS devices via their
ethernet address.
* Linux daemon that implements the MAC Telnet Daemon to permit connecting
to Linux machines via their ethernet address.

Forked to implement additional client and daemon that tunnels ssh connection
through the MAC Telnet protocol to permit connecting to Linux machines via
their ethernet address using SSH protocol.

Using the SSH protocol mactelnet.users file is not requiered. Public key
authentication works seamlessly permiting logins without password.

The SSH versions of the client and daemon are not compatible with the Telnet
versions.


Installation
------------

Clone repository.

Then:
    make all install

Now you're ready.


Usage: mactelnet
----------------

    # mactelnet -h
    Usage: mactelnet <MAC|identity> [-h] [-n] [-t <timeout>] [-u <username>] [-p <password>]
    
    Parameters:
      MAC       MAC-Address of the RouterOS device. Use mndp to discover them.
      identity  The identity/name of your RouterOS device. Uses MNDP protocol to find it..
      -n        Do not use broadcast packets. Less insecure but requires root privileges.
      -t        Amount of seconds to wait for a response on each interface.
      -u        Specify username on command line.
      -p        Specify password on command line.
      -h        This help.


Example:

    $ mactelnet 0:c:42:43:58:a5 -u admin
    Password: 
    Connecting to 0:c:42:43:58:a5...done


Usage: macping
--------------

    # macping -h
    Usage: macping <MAC> [-h] [-c <count>] [-s <packet size>]
    
    Parameters:
      MAC       MAC-Address of the RouterOS/mactelnetd device.
      -s        Specify size of ping packet.
      -c        Number of packets to send. (0 = for ever)
      -h        This help.

Example:

    # macping 0:c:42:43:58:a5
    0:c:42:43:58:a5 56 byte, ping time 1.17 ms
    0:c:42:43:58:a5 56 byte, ping time 1.07 ms
    0:c:42:43:58:a5 56 byte, ping time 1.20 ms
    0:c:42:43:58:a5 56 byte, ping time 0.65 ms
    0:c:42:43:58:a5 56 byte, ping time 1.19 ms
    
    5 packets transmitted, 5 packets received, 0% packet loss
    round-trip min/avg/max = 0.65/1.06/1.20 ms

Or for use in bash-scripting:

    # macping 0:c:42:43:58:a5 -c 2 >/dev/null 2>&1 || ( echo "No answer for 2 pings" | mail -s "router down" my.email@address.com )


Usage: mactelnetd
-----------------

    # mactelnetd -h
    Usage: ./mactelnetd [-f|-n|-h]
    
    Parameters:
      -f        Run process in foreground.
      -n        Do not use broadcast packets. Just a tad less insecure.
      -h        This help.


Usage: macssh
-------------

    # macssh -h
    Usage: ./macssh <MAC|identity> [-h] [-n] [-u] [-t <timeout>]

    Parameters:
      MAC       MAC-Address of the RouterOS/mactelnetd device. Use mndp to discover it.
      identity  The identity/name of your destination device. Uses MNDP protocol to find it.
      -n        Do not use broadcast packets. Less insecure but requires root privileges.
      -t        Amount of seconds to wait for a response on each interface.
      -u        Specify username on command line.
      -h        This help.


Usage: macsshd
--------------

    # macsshd -h
    Usage: ./macsshd [-f|-n|-h] -p PORT

    Parameters:
      -f        Run process in foreground.
      -n        Do not use broadcast packets. Just a tad less insecure.
      -p        Destination port.
      -h        This help.

