/*
    Mac-Telnet - Connect to RouterOS or mactelnetd devices via MAC address
    Copyright (C) 2010, Håkon Nessjøen <haakon.nessjoen@gmail.com>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/
#include <libintl.h>
#include <locale.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <string.h>
#include "protocol.h"
#include "config.h"
#include "interfaces.h"

#define _(String) gettext (String)

/* This file is also used for the -l option in mactelnet */
#ifndef FROM_MACTELNET

/* Protocol data direction, not used here, but obligatory for protocol.c */
unsigned char mt_direction_fromserver = 0;

int main(int argc, char **argv)  {
	int batch_mode = 0;
	char *iface = NULL;
#else

void sig_alarm(int signo)
{
	exit(0);
}

int mndp(int timeout, int batch_mode, char *iface)  {
#endif
	int sock, result;
	int optval = 1;
	struct sockaddr_in si_me, si_remote;
	unsigned char buff[MT_PACKET_LEN];

#ifdef FROM_MACTELNET
	/* mactelnet.c has this set to 1 */
	mt_direction_fromserver = 0;
	signal(SIGALRM, sig_alarm);
#endif

	setlocale(LC_ALL, "");
	bindtextdomain("mactelnet", "/usr/share/locale");
	textdomain("mactelnet");

	/* Open a UDP socket handle */
	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	// Add special case *, dont bind to it, it is to send discovery packet to all interfaces
	if (iface != NULL && iface[0] != '%') {
		size_t len = strlen(iface);
		int r = setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, iface, len);
		if (r) {
			fprintf(stderr, _("Error binding to interface %s\n"), iface);
			perror("");
			//return 1;
		}
	}

	/* Set initialize address/port */
	memset((char *) &si_me, 0, sizeof(si_me));
	si_me.sin_family = AF_INET;
	si_me.sin_port = htons(MT_MNDP_PORT);
	si_me.sin_addr.s_addr = htonl(INADDR_ANY);

	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof (optval));

	/* Bind to specified address/port */
	if (bind(sock, (struct sockaddr *)&si_me, sizeof(si_me)) == -1) {
		fprintf(stderr, _("Error binding to %s:%d\n"), inet_ntoa(si_me.sin_addr), MT_MNDP_PORT);
		return 1;
	}

	/* Write informative message to STDERR to make it easier to use the output in simple scripts */
	fprintf(stderr, _("Searching for MikroTik routers... Abort with CTRL+C.\n"));

	/* Set the socket to allow sending broadcast packets */
	if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &optval, sizeof (optval)) == -1) {
		fprintf(stderr, _("Unable to send broadcast packets: Operating in receive only mode.\n"));
	} else {
		/* Request routers identify themselves */
		unsigned int message = 0;

		memset((char *) &si_remote, 0, sizeof(si_remote));
		si_remote.sin_family = AF_INET;
		si_remote.sin_port = htons(MT_MNDP_PORT);
		si_remote.sin_addr.s_addr = htonl(INADDR_BROADCAST);
		if (sendto (sock, &message, sizeof (message), 0, (struct sockaddr *)&si_remote, sizeof(si_remote)) == -1) {
			fprintf(stderr, _("Unable to send broadcast packet: Operating in receive only mode.\n"));
		}
		// This means send discovery request to all available interfaces
		if (iface != NULL && iface[0] == '*') {
			struct net_interface *interfaces;
			interfaces = malloc(sizeof(struct net_interface) * MAX_INTERFACES);
			bzero(interfaces, sizeof(struct net_interface) * MAX_INTERFACES);
			if (net_get_interfaces(interfaces, MAX_INTERFACES) <= 0) {
				fprintf(stderr, _("Error: No suitable devices found\n"));
				//exit(1);
			}
			for (int i = 0; i < MAX_INTERFACES; ++i) {
				if (!interfaces[i].in_use)
					break;

				/* Skip loopback interfaces */
				if (memcmp("lo", interfaces[i].name, 2) == 0)
					continue;

				size_t len = strlen(interfaces[i].name);
				if (len > 0) {
					int r = setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, interfaces[i].name, len);
					if (r) {
						fprintf(stderr, _("Error binding to interface %s\n"), interfaces[i].name);
						perror("");
						//return 1;
					}

				}
			}
			// Remove binding
			setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, "", 0);
			free(interfaces);
		}
	}
	if (batch_mode) {
		printf("%s\n", _("MAC-Address,Identity,Platform,Version,Hardware,Uptime,Softid,Ifname"));
	} else {
		printf("\n\E[1m%-17s %s\E[m\n", _("MAC-Address"), _("Identity (platform version hardware) uptime"));
	}
#ifdef FROM_MACTELNET
	if (timeout > 0) {
		alarm(timeout);
	}
#endif

	while (1) {
		struct mt_mndp_info *packet;
		struct sockaddr_in srcaddr;
		socklen_t srcaddr_sz = sizeof(srcaddr);
		/* Wait for a UDP packet */
		result = recvfrom(sock, buff, MT_PACKET_LEN, 0, (struct sockaddr *) &srcaddr, (socklen_t*)&srcaddr_sz);
		if (result < 0) {
			fprintf(stderr, _("An error occured. aborting\n"));
			exit(1);
		}

		/* Parse MNDP packet */
		packet = parse_mndp(buff, result);

		if (packet != NULL && !batch_mode) {
			/* Print it */
			if (srcaddr_sz > 0)
				printf("(%s) ", inet_ntoa(srcaddr.sin_addr));
			printf("%-17s %s", ether_ntoa((struct ether_addr *)packet->address), packet->identity);
			if (packet->platform != NULL) {
				printf(" (%s %s %s)", packet->platform, packet->version, packet->hardware);
			}
			if (packet->softid != NULL) {
				printf("  %s", packet->softid);
			}
			if (packet->uptime > 0) {
				printf(_("  up %d days %d hours"), packet->uptime / 86400, packet->uptime % 86400 / 3600);
			}
			if (packet->softid != NULL) {
				printf("  %s", packet->softid);
			}
			if (packet->ifname != NULL) {
				printf(" %s", packet->ifname);
			}
			putchar('\n');
		} else if (packet != NULL) {
			/* Print it */
			printf("'%s','%s',", ether_ntoa((struct ether_addr *)packet->address), packet->identity);
			printf("'%s','%s','%s',", packet->platform, packet->version, packet->hardware);
			printf("'%d','%s','%s'", packet->uptime, packet->softid, packet->ifname);
			putchar('\n');
			fflush(stdout);
		}
	}

	/* We'll never get here.. */
	return 0;
}
