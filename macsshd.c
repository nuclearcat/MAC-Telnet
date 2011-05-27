/*
    Mac-SSHD - Daemon that tunnels ssh connections from macssh on remote 
    devices to local SSH Daemon via MAC address.
	Shameless hack by Ali Onur Uyar of code for mactelnetd by Håkon Nessjøen.
    Copyright (C) 2010, Håkon Nessjøen <haakon.nessjoen@gmail.com>
    Copyright (C) 2011, Ali Onur Uyar <aouyar@gmail.com>

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
#define _XOPEN_SOURCE 600
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <sys/time.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <linux/if_ether.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <syslog.h>
#include <sys/utsname.h>
#include "protocol.h"
#include "udp.h"
#include "devices.h"
#include "config.h"

#define PROGRAM_NAME "MAC-Telnet Daemon"
#define PROGRAM_VERSION "0.3"

#define MAX_INSOCKETS 100

#define MT_INTERFACE_LEN 128

/* Max ~5 pings per second */
#define MT_MAXPPS MT_MNDP_BROADCAST_INTERVAL * 5

struct mt_socket {
	unsigned char ip[4];
	unsigned char mac[ETH_ALEN];
	char name[MT_INTERFACE_LEN];
	int sockfd;
	int device_index;
};

static int sockfd;
static int insockfd;
static int mndpsockfd;

static int pings = 0;

static struct mt_socket sockets[MAX_INSOCKETS];
static int sockets_count = 0;

static int use_raw_socket = 0;

static struct in_addr sourceip; 
static struct in_addr destip;
static int sourceport;
static int termport = 22;

static time_t last_mndp_time = 0;

/* Protocol data direction */
unsigned char mt_direction_fromserver = 1;

/* Anti-timeout is every 10 seconds. Give up after 15. */
#define MT_CONNECTION_TIMEOUT 15

/* Connection states */
enum mt_connection_state {
	STATE_AUTH,
	STATE_CLOSED,
	STATE_ACTIVE
};

/** Connection struct */
struct mt_connection {
	struct mt_socket *socket;
	unsigned short seskey;
	unsigned int incounter;
	unsigned int outcounter;
	time_t lastdata;

	enum mt_connection_state state;
	int pid;
	int wait_for_ack;
	int fwdfd;

	char username[30];
	unsigned char srcip[4];
	unsigned char srcmac[6];
	unsigned short srcport;
	unsigned char dstmac[6];
	unsigned char enckey[16];

	struct mt_connection *next;
};

static struct mt_connection *connections_head = NULL;

static void list_add_connection(struct mt_connection *conn) {
	struct mt_connection *p;
	struct mt_connection *last;
	if (connections_head == NULL) {
		connections_head = conn;
		connections_head->next = NULL;
		return;
	}
	for (p = connections_head; p != NULL; p = p->next) {last = p;}
	last->next = conn;
	conn->next = NULL;
}

static void list_remove_connection(struct mt_connection *conn) {
	struct mt_connection *p;
	struct mt_connection *last;
	if (connections_head == NULL) {
		return;
	}

	if (conn->state == STATE_ACTIVE && conn->fwdfd > 0) {
		close(conn->fwdfd);
	}

	if (connections_head == conn) {
		connections_head = conn->next;
		free(conn);
		return;
	}

	for (p = connections_head; p != NULL; p = p->next) {
		if (p == conn) {
			last->next = p->next;
			free(p);
			return;
		}
		last = p;
	}
}

static struct mt_connection *list_find_connection(unsigned short seskey, unsigned char *srcmac) {
	struct mt_connection *p;

	if (connections_head == NULL) {
		return NULL;
	}

	for (p = connections_head; p != NULL; p = p->next) {
		if (p->seskey == seskey && memcmp(srcmac, p->srcmac, 6) == 0) {
			return p;
		}
	}

	return NULL;
}

static int find_socket(unsigned char *mac) {
	int i;

	for (i = 0; i < sockets_count; ++i) {
		if (memcmp(mac, sockets[i].mac, ETH_ALEN) == 0) {
			return i;
		}
	}
	return -1;
}

static void setup_sockets() {
	struct sockaddr_in myip;
	char devicename[MT_INTERFACE_LEN];
	unsigned char mac[ETH_ALEN];
	unsigned char emptymac[ETH_ALEN];
	int success;

	memset(emptymac, 0, ETH_ALEN);

	while ((success = get_macs(insockfd, devicename, MT_INTERFACE_LEN, mac))) {
		if (memcmp(mac, emptymac, ETH_ALEN) != 0 && find_socket(mac) < 0) {
			int optval = 1;
			struct sockaddr_in si_me;
			struct mt_socket *mysocket = &(sockets[sockets_count]);

			memcpy(mysocket->mac, mac, ETH_ALEN);
			strncpy(mysocket->name, devicename, MT_INTERFACE_LEN - 1);
			mysocket->name[MT_INTERFACE_LEN - 1] = '\0';

			if (get_device_ip(insockfd, devicename, &myip) > 0) {

				mysocket->sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
				if (mysocket->sockfd < 0) {
					close(mysocket->sockfd);
					continue;
				}

				if (setsockopt(mysocket->sockfd, SOL_SOCKET, SO_BROADCAST, &optval, sizeof (optval))==-1) {
					perror("SO_BROADCAST");
					continue;
				}

				setsockopt(mysocket->sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

				/* Initialize receiving socket on the device chosen */
				si_me.sin_family = AF_INET;
				si_me.sin_port = htons(MT_MACTELNET_PORT);
				memcpy(&(si_me.sin_addr), &(myip.sin_addr), 4);

				if (bind(mysocket->sockfd, (struct sockaddr *)&si_me, sizeof(si_me))==-1) {
					fprintf(stderr, "Error binding to %s:%d, %s\n", inet_ntoa(si_me.sin_addr), sourceport, strerror(errno));
					continue;
				}
				memcpy(mysocket->ip, &(myip.sin_addr), 4);
			}
			mysocket->device_index = get_device_index(insockfd, devicename);
			
			sockets_count++;
		}
	}
}

static int send_udp(const struct mt_connection *conn, const struct mt_packet *packet) {
	if (use_raw_socket) {
		return send_custom_udp(sockfd, conn->socket->device_index, conn->dstmac, conn->srcmac, &sourceip, sourceport, &destip, conn->srcport, packet->data, packet->size);
	} else {
		/* Init SendTo struct */
		struct sockaddr_in socket_address;
		socket_address.sin_family = AF_INET;
		socket_address.sin_port = htons(conn->srcport);
		socket_address.sin_addr.s_addr = htonl(INADDR_BROADCAST);

		return sendto(conn->socket->sockfd, packet->data, packet->size, 0, (struct sockaddr*)&socket_address, sizeof(socket_address));
	}
}

static int send_special_udp(const struct mt_socket *sock, unsigned short port, const struct mt_packet *packet) {
	unsigned char dstmac[6];
	
	if (use_raw_socket) {
		memset(dstmac, 0xff, 6);
		return send_custom_udp(sockfd, sock->device_index, sock->mac, dstmac, (const struct in_addr *)sock->ip, port, &destip, port, packet->data, packet->size);
	} else {
		/* Init SendTo struct */
		struct sockaddr_in socket_address;
		socket_address.sin_family = AF_INET;
		socket_address.sin_port = htons(port);
		socket_address.sin_addr.s_addr = htonl(INADDR_BROADCAST);

		return sendto(sock->sockfd, packet->data, packet->size, 0, (struct sockaddr*)&socket_address, sizeof(socket_address));
	}
}

static void abort_connection(struct mt_connection *curconn, struct mt_mactelnet_hdr *pkthdr, char *message) {
	struct mt_packet pdata;
	
	init_packet(&pdata, MT_PTYPE_DATA, pkthdr->dstaddr, pkthdr->srcaddr, pkthdr->seskey, curconn->outcounter);
	add_control_packet(&pdata, MT_CPTYPE_PLAINDATA, message, strlen(message));
	send_udp(curconn, &pdata);

	/* Make connection time out; lets the previous message get acked before disconnecting */
	curconn->state = STATE_CLOSED;
	init_packet(&pdata, MT_PTYPE_END, pkthdr->dstaddr, pkthdr->srcaddr, pkthdr->seskey, curconn->outcounter);
	send_udp(curconn, &pdata);
}

static void user_login(struct mt_connection *curconn, struct mt_mactelnet_hdr *pkthdr) {
	struct mt_packet pdata;

	init_packet(&pdata, MT_PTYPE_DATA, pkthdr->dstaddr, pkthdr->srcaddr, pkthdr->seskey, curconn->outcounter);
	curconn->outcounter += add_control_packet(&pdata, MT_CPTYPE_END_AUTH, NULL, 0);
	send_udp(curconn, &pdata);

	if (curconn->state == STATE_ACTIVE) {
		return;
	}
	
	/* Connect to terminal server port using this socket. */
	curconn->fwdfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (curconn->fwdfd < 0) {
		syslog(LOG_ERR, "Socket creation error: %s", strerror(errno));
		abort_connection(curconn, pkthdr, "Socket error.\r\n");
		return;
	}
	int optval = 1;
	if(setsockopt(curconn->fwdfd, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval)) < 0) {
		abort_connection(curconn, pkthdr, "Socket error.\r\n");
		perror("SO_KEEPALIVE");
		return;
	}
	
	/* Connect to terminal server port */
	struct sockaddr_in socket_address;
	memset(&socket_address, 0, sizeof(socket_address));
	socket_address.sin_family = AF_INET;
	socket_address.sin_port = htons(termport);
	socket_address.sin_addr.s_addr = inet_addr("127.0.0.1");
	if (connect(curconn->fwdfd, (struct sockaddr *) &socket_address, sizeof(socket_address)) < 0) {
		syslog(LOG_ERR, "Error in connection to terminal server: %s", strerror(errno));
		abort_connection(curconn, pkthdr, "Terminal server connection error.\r\n");
		return;
    }

	/* User is logged in */
	curconn->state = STATE_ACTIVE;
}

static void handle_data_packet(struct mt_connection *curconn, struct mt_mactelnet_hdr *pkthdr, int data_len) {
	struct mt_mactelnet_control_hdr cpkt;
	unsigned char *data = pkthdr->data;
	int got_auth_packet = 0;
	int success;

	/* Parse first control packet */
	success = parse_control_packet(data, data_len - MT_HEADER_LEN, &cpkt);

	while (success) {
		if (cpkt.cptype == MT_CPTYPE_BEGINAUTH) {
			got_auth_packet = 1;
		} else if (cpkt.cptype == MT_CPTYPE_PLAINDATA) {

			/* relay data from client to terminal service. */
			if (curconn->state == STATE_ACTIVE && curconn->fwdfd != -1) {
				if (send(curconn->fwdfd, cpkt.data, cpkt.length, 0) <= 0) {
					syslog(LOG_INFO, "(%d) Terminal server connection closed.", curconn->seskey);
					abort_connection(curconn, pkthdr, "Terminal server disconnection.\r\n");
					return;
				}
			}
		} else {
			syslog(LOG_WARNING, "(%d) Unhandeled control packet type: %d", curconn->seskey, cpkt.cptype);
		}

		/* Parse next control packet */
		success = parse_control_packet(NULL, 0, &cpkt);
	}
	
	if (got_auth_packet) {
		user_login(curconn, pkthdr);
	}
	
}

static void terminate() {
	syslog(LOG_NOTICE, "Exiting.");
	exit(0);
}

static void handle_packet(unsigned char *data, int data_len, const struct sockaddr_in *address) {
	struct mt_mactelnet_hdr pkthdr;
	struct mt_connection *curconn = NULL;
	struct mt_packet pdata;
	int socketnum;
	int i;

	parse_packet(data, &pkthdr);

	/* Drop packets not belonging to us */
	if ((socketnum = find_socket(pkthdr.dstaddr)) < 0) {
		return;
	}

	switch (pkthdr.ptype) {

		case MT_PTYPE_PING:
			if (pings++ > MT_MAXPPS) {
				break;
			}
			init_pongpacket(&pdata, (unsigned char *)&(pkthdr.dstaddr), (unsigned char *)&(pkthdr.srcaddr));
			add_packetdata(&pdata, pkthdr.data - 4, data_len - (MT_HEADER_LEN - 4));
			for (i = 0; i < sockets_count; ++i) {
				struct mt_socket *socket = &(sockets[i]);
				if (memcmp(&(socket->mac), &(pkthdr.dstaddr), ETH_ALEN) == 0) {
					send_special_udp(socket, MT_MACTELNET_PORT, &pdata);
					break;
				}
			}
			break;

		case MT_PTYPE_SESSIONSTART:
			syslog(LOG_DEBUG, "(%d) New connection from %s.", pkthdr.seskey, ether_ntoa((struct ether_addr*)&(pkthdr.srcaddr)));
			curconn = calloc(1, sizeof(struct mt_connection));
			curconn->seskey = pkthdr.seskey;
			curconn->lastdata = time(NULL);
			curconn->state = STATE_AUTH;
			curconn->socket = &(sockets[socketnum]);
			memcpy(curconn->srcmac, pkthdr.srcaddr, 6);
			memcpy(curconn->srcip, &(address->sin_addr), 4);
			curconn->srcport = htons(address->sin_port);
			memcpy(curconn->dstmac, pkthdr.dstaddr, 6);

			list_add_connection(curconn);

			init_packet(&pdata, MT_PTYPE_ACK, pkthdr.dstaddr, pkthdr.srcaddr, pkthdr.seskey, pkthdr.counter);
			send_udp(curconn, &pdata);
			break;

		case MT_PTYPE_END:
			curconn = list_find_connection(pkthdr.seskey, (unsigned char *)&(pkthdr.srcaddr));
			if (curconn == NULL) {
				break;
			}
			if (curconn->state != STATE_CLOSED) {
				init_packet(&pdata, MT_PTYPE_END, pkthdr.dstaddr, pkthdr.srcaddr, pkthdr.seskey, pkthdr.counter);
				send_udp(curconn, &pdata);
			}
			syslog(LOG_DEBUG, "(%d) Connection closed.", curconn->seskey);
			list_remove_connection(curconn);
			return;

		case MT_PTYPE_ACK:
			curconn = list_find_connection(pkthdr.seskey, (unsigned char *)&(pkthdr.srcaddr));
			if (curconn == NULL) {
				break;
			}

			if (pkthdr.counter <= curconn->outcounter) {
				curconn->wait_for_ack = 0;
			}

			if (time(0) - curconn->lastdata > 9) {
				// Answer to anti-timeout packet
				init_packet(&pdata, MT_PTYPE_ACK, pkthdr.dstaddr, pkthdr.srcaddr, pkthdr.seskey, pkthdr.counter);
				send_udp(curconn, &pdata);
			}
			curconn->lastdata = time(NULL);
			return;

		case MT_PTYPE_DATA:
			curconn = list_find_connection(pkthdr.seskey, (unsigned char *)&(pkthdr.srcaddr));
			if (curconn == NULL) {
				break;
			}
			curconn->lastdata = time(NULL);

			/* ack the data packet */
			init_packet(&pdata, MT_PTYPE_ACK, pkthdr.dstaddr, pkthdr.srcaddr, pkthdr.seskey, pkthdr.counter + (data_len - MT_HEADER_LEN));
			send_udp(curconn, &pdata);

			/* Accept first packet, and all packets greater than incounter, and if counter has
			wrapped around. */
			if (curconn->incounter == 0 || pkthdr.counter > curconn->incounter || (curconn->incounter - pkthdr.counter) > 16777216) {
				curconn->incounter = pkthdr.counter;
			} else {
				/* Ignore double or old packets */
				return;
			}

			handle_data_packet(curconn, &pkthdr, data_len);
			break;
		default:
			if (curconn) {
				syslog(LOG_WARNING, "(%d) Unhandeled packet type: %d", curconn->seskey, pkthdr.ptype);
				init_packet(&pdata, MT_PTYPE_ACK, pkthdr.dstaddr, pkthdr.srcaddr, pkthdr.seskey, pkthdr.counter);
				send_udp(curconn, &pdata);
			}
		}
	if (0 && curconn != NULL) {
		printf("Packet, incounter %d, outcounter %d\n", curconn->incounter, curconn->outcounter);
	}
}

static void daemonize() {
	int pid,fd;

	pid = fork();

	/* Error? */
	if (pid < 0) {
		exit(1);
	}

	/* Parent exit */
	if (pid > 0) {
		exit(0);
	}

	setsid();
	close(0);
	close(1);
	close(2);
	
	fd = open("/dev/null",O_RDWR);
	dup(fd);
	dup(fd);

	signal(SIGCHLD,SIG_IGN);
	signal(SIGTSTP,SIG_IGN);
	signal(SIGTTOU,SIG_IGN);
	signal(SIGTTIN,SIG_IGN);
	signal(SIGPIPE,SIG_IGN);
}

static void print_version() {
	fprintf(stderr, PROGRAM_NAME " " PROGRAM_VERSION "\n");
}

void mndp_broadcast() {
	struct mt_packet pdata;
	struct utsname s_uname;
	struct sysinfo s_sysinfo;
	int i;
	unsigned int uptime;

	if (uname(&s_uname) != 0) {
		return;
	}

	if (sysinfo(&s_sysinfo) != 0) {
		return;
	}

	uptime = s_sysinfo.uptime;

	/* Seems like ping uptime is transmitted as little endian? */
#if BYTE_ORDER == BIG_ENDIAN
	uptime = (
		((uptime & 0x000000FF) << 24) +
		((uptime & 0x0000FF00) << 8) +
		((uptime & 0x00FF0000) >> 8) +
		((uptime & 0xFF000000) >> 24)
	);
#endif

	for (i = 0; i < sockets_count; ++i) {
		struct mt_mndp_hdr *header = (struct mt_mndp_hdr *)&(pdata.data);
		struct mt_socket *socket = &(sockets[i]);

		mndp_init_packet(&pdata, 0, 1);
		mndp_add_attribute(&pdata, MT_MNDPTYPE_ADDRESS, socket->mac, 6);
		mndp_add_attribute(&pdata, MT_MNDPTYPE_IDENTITY, s_uname.nodename, strlen(s_uname.nodename));
		mndp_add_attribute(&pdata, MT_MNDPTYPE_VERSION, s_uname.release, strlen(s_uname.release));
		mndp_add_attribute(&pdata, MT_MNDPTYPE_PLATFORM, PLATFORM_NAME, strlen(PLATFORM_NAME));
		mndp_add_attribute(&pdata, MT_MNDPTYPE_HARDWARE, s_uname.machine, strlen(s_uname.machine));
		mndp_add_attribute(&pdata, MT_MNDPTYPE_TIMESTAMP, &uptime, 4);

		header->cksum = in_cksum((unsigned short *)&(pdata.data), pdata.size);

		send_special_udp(socket, MT_MNDP_PORT, &pdata);
	}
}

/*
 * TODO: Rewrite main() when all sub-functionality is tested
 */
int main (int argc, char **argv) {
	int result,i;
	struct sockaddr_in si_me;
	struct sockaddr_in si_me_mndp;
	struct timeval timeout;
	struct mt_packet pdata;
	fd_set read_fds;
	int c,optval = 1;
	int print_help = 0;
	int foreground = 0;

	while ((c = getopt(argc, argv, "fnvhp:?")) != -1) {
		switch (c) {
			case 'f':
				foreground = 1;
				break;

			case 'n':
				use_raw_socket = 1;
				break;
				
			case 'p':
				termport = atoi(optarg);
				break;

			case 'v':
				print_version();
				exit(0);
				break;

			case 'h':
			case '?':
				print_help = 1;
				break;

		}
	}

	if (print_help) {
		print_version();
		fprintf(stderr, "Usage: %s [-f|-n|-h] -p PORT\n", argv[0]);

		if (print_help) {
			fprintf(stderr, "\nParameters:\n");
			fprintf(stderr, "  -f        Run process in foreground.\n");
			fprintf(stderr, "  -n        Do not use broadcast packets. Just a tad less insecure.\n");
			fprintf(stderr, "  -p        Destination port.\n");
			fprintf(stderr, "  -h        This help.\n");
			fprintf(stderr, "\n");
		}
		return 1;
	}

	if (geteuid() != 0) {
		fprintf(stderr, "You need to have root privileges to use %s.\n", argv[0]);
		return 1;
	}

	/* Seed randomizer */
	srand(time(NULL));

	if (use_raw_socket) {
		/* Transmit raw packets with this socket */
		sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
		if (sockfd < 0) {
			perror("sockfd");
			return 1;
		}
	}

	/* Receive regular udp packets with this socket */
	insockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (insockfd < 0) {
		perror("insockfd");
		return 1;
	}

	/* Set random source port */
	sourceport = MT_MACTELNET_PORT;

	/* Listen address*/
	inet_pton(AF_INET, (char *)"0.0.0.0", &sourceip);

	/* Set up global info about the connection */
	inet_pton(AF_INET, (char *)"255.255.255.255", &destip);

	/* Initialize receiving socket on the device chosen */
	memset((char *) &si_me, 0, sizeof(si_me));
	si_me.sin_family = AF_INET;
	si_me.sin_port = htons(sourceport);
	memcpy(&(si_me.sin_addr), &sourceip, 4);

	setsockopt(insockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof (optval));

	/* Bind to udp port */
	if (bind(insockfd, (struct sockaddr *)&si_me, sizeof(si_me))==-1) {
		fprintf(stderr, "Error binding to %s:%d, %s\n", inet_ntoa(si_me.sin_addr), sourceport, strerror(errno));
		return 1;
	}

	/* TODO: Move socket initialization out of main() */

	/* Receive mndp udp packets with this socket */
	mndpsockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (insockfd < 0) {
		perror("insockfd");
		return 1;
	}

	memset((char *)&si_me_mndp, 0, sizeof(si_me_mndp));
	si_me_mndp.sin_family = AF_INET;
	si_me_mndp.sin_port = htons(MT_MNDP_PORT);
	memcpy(&(si_me_mndp.sin_addr), &sourceip, 4);

	setsockopt(mndpsockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof (optval));

	/* Bind to udp port */
	if (bind(mndpsockfd, (struct sockaddr *)&si_me_mndp, sizeof(si_me_mndp))==-1) {
		fprintf(stderr, "Error binding to %s:%d, %s\n", inet_ntoa(si_me_mndp.sin_addr), MT_MNDP_PORT, strerror(errno));
	}

	setup_sockets();

	if (!foreground) {
		daemonize();
	}

	openlog("mactelnetd", LOG_PID, LOG_DAEMON);

	syslog(LOG_NOTICE, "Bound to %s:%d", inet_ntoa(si_me.sin_addr), sourceport);

	for (i = 0; i < sockets_count; ++i) {
		struct mt_socket *socket = &(sockets[i]);
		syslog(LOG_NOTICE, "Listening on %s for %16s\n", socket->name, ether_ntoa((struct ether_addr *)socket->mac));
	}
	
	if (sockets_count == 0) {
		syslog(LOG_ERR, "Unable to find the mac-address on any interfaces\n");
		exit(1);
	}

	signal(SIGTERM, terminate);

	while (1) {
		int reads;
		struct mt_connection *p;
		int maxfd=0;
		time_t now;

		/* Init select */
		FD_ZERO(&read_fds);
		FD_SET(insockfd, &read_fds);
		FD_SET(mndpsockfd, &read_fds);
		maxfd = insockfd > mndpsockfd ? insockfd : mndpsockfd;
		
		/* Add active connections to select queue */
		for (p = connections_head; p != NULL; p = p->next) {
			if (p->state == STATE_ACTIVE && p->wait_for_ack == 0 && p->fwdfd > 0) {
				FD_SET(p->fwdfd, &read_fds);
				if (p->fwdfd > maxfd) {
					maxfd = p->fwdfd;
				}
			}
		}

		timeout.tv_sec = 1;
		timeout.tv_usec = 0;

		/* Wait for data or timeout */
		reads = select(maxfd+1, &read_fds, NULL, NULL, &timeout);
		if (reads > 0) {
			/* Handle data from clients
			 TODO: Enable broadcast support (without raw sockets)
			 */
			if (FD_ISSET(insockfd, &read_fds)) {
				unsigned char buff[1500];
				struct sockaddr_in saddress;
				unsigned int slen = sizeof(saddress);
				result = recvfrom(insockfd, buff, 1500, 0, (struct sockaddr *)&saddress, &slen);
				handle_packet(buff, result, &saddress);
			}
			if (FD_ISSET(mndpsockfd, &read_fds)) {
				unsigned char buff[1500];
				struct sockaddr_in saddress;
				unsigned int slen = sizeof(saddress);
				result = recvfrom(mndpsockfd, buff, 1500, 0, (struct sockaddr *)&saddress, &slen);

				/* Handle MNDP broadcast request, max 1 rps */
				if (result == 4 && time(NULL) - last_mndp_time > 0) {
					mndp_broadcast();
					time(&last_mndp_time);
				}
			}
			/* Handle data from terminal sessions */
			for (p = connections_head; p != NULL; p = p->next) {
				/* Check if we have data ready in the terminal server buffer for the active session */
				if (p->state == STATE_ACTIVE && p->fwdfd > 0 && p->wait_for_ack == 0 && FD_ISSET(p->fwdfd, &read_fds)) {
					unsigned char keydata[1024];
					int datalen,plen;

					/* Read it */
					datalen = read(p->fwdfd, &keydata, 1024);
					if (datalen > 0) {
						/* Send it */
						init_packet(&pdata, MT_PTYPE_DATA, p->dstmac, p->srcmac, p->seskey, p->outcounter);
						plen = add_control_packet(&pdata, MT_CPTYPE_PLAINDATA, &keydata, datalen);
						p->outcounter += plen;
						p->wait_for_ack = 1;
						result = send_udp(p, &pdata);
					} else {
						/* Shell exited */
						struct mt_connection tmp;
						init_packet(&pdata, MT_PTYPE_END, p->dstmac, p->srcmac, p->seskey, p->outcounter);
						send_udp(p, &pdata);
						syslog(LOG_INFO, "(%d) Terminal server disconnected.", p->seskey);
						tmp.next = p->next;
						list_remove_connection(p);
						p = &tmp;
					}
				}
				else if (p->state == STATE_ACTIVE && p->fwdfd > 0 && p->wait_for_ack == 1 && FD_ISSET(p->fwdfd, &read_fds)) {
					printf("(%d) Waiting for ack\n", p->seskey);
				}
			}
		/* Handle select() timeout */
		}
		time(&now);
		
		if (now - last_mndp_time > MT_MNDP_BROADCAST_INTERVAL) {
			pings = 0;
			mndp_broadcast();
			last_mndp_time = now;
		}
		if (connections_head != NULL) {
			struct mt_connection *p,tmp;
			for (p = connections_head; p != NULL; p = p->next) {
				if (now - p->lastdata >= MT_CONNECTION_TIMEOUT) {
					syslog(LOG_INFO, "(%d) Session timed out", p->seskey);
					init_packet(&pdata, MT_PTYPE_DATA, p->dstmac, p->srcmac, p->seskey, p->outcounter);
					add_control_packet(&pdata, MT_CPTYPE_PLAINDATA, "Timeout\r\n", 9);
					send_udp(p, &pdata);
					init_packet(&pdata, MT_PTYPE_END, p->dstmac, p->srcmac, p->seskey, p->outcounter);
					send_udp(p, &pdata);

					tmp.next = p->next;
					list_remove_connection(p);
					p = &tmp;
				}
			}
		}
	}

	close(sockfd);
	close(insockfd);
	for (i = 0; i < sockets_count; ++i) {
		close(sockets[i].sockfd);
	}
	closelog();
	return 0;
}
