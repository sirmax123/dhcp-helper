/* dhcp-helper is Copyright (c) 2004,2008 Simon Kelley

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 dated June, 1991, or
   (at your option) version 3 dated 29 June, 2007.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/* Author's email: simon@thekelleys.org.uk */

#define COPYRIGHT "Copyright (C) 2004-2012 Simon Kelley" 

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <limits.h>
#include <net/if.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <netdb.h>
#include <linux/types.h>
#include <linux/capability.h>
/* There doesn't seem to be a universally-available 
   userpace header for this. */
extern int capset(cap_user_header_t header, cap_user_data_t data);
extern int capget(cap_user_header_t header, cap_user_data_t data);
#define LINUX_CAPABILITY_VERSION_1  0x19980330
#define LINUX_CAPABILITY_VERSION_2  0x20071026
#define LINUX_CAPABILITY_VERSION_3  0x20080522

#include <sys/prctl.h>
#include <net/if_arp.h>

#define PIDFILE "/var/run/dhcp-helper.pid"
#define USER "nobody"

#define DHCP_CHADDR_MAX  16
#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68
#define DHCP_SERVER_ALTPORT 1067
#define DHCP_CLIENT_ALTPORT 1068
#define BOOTREQUEST      1
#define BOOTREPLY        2

struct namelist {
  char name[IF_NAMESIZE];
/* Internet address. */
//      struct in_addr {
//               uint32_t       s_addr;     /* address in network byte order */
//      };
  struct in_addr addr;
  struct namelist *next;
};

struct interface {
  int index;
  struct in_addr addr;
  struct interface *next;
  char name[IF_NAMESIZE];
};

struct dhcp_packet_with_opts{
  struct dhcp_packet {
    unsigned char op, htype, hlen, hops;
    unsigned int xid;
    unsigned short secs, flags;
    struct in_addr ciaddr, yiaddr, siaddr, giaddr;
    unsigned char chaddr[DHCP_CHADDR_MAX], sname[64], file[128];
  } header;
  unsigned char options[312];
};


int main(int argc, char **argv)
{
    int bootrequest_packets_count = 0;
    int bootreply_packets_count = 0;
    int other_packets_count = 0;
    int all_packets_count = 0;

    int fd = -1, oneopt = 1, mtuopt = IP_PMTUDISC_DONT;
// https://www.opennet.ru/man.shtml?topic=netdevice&category=7&russian=0
//struct ifreq {
//    char            ifr_name[IFNAMSIZ];   /* Имя интерфейса */
//    union {
//                    struct sockaddr       ifr_addr;
//                    struct sockaddr       ifr_dstaddr;
//                    struct sockaddr       ifr_broadaddr;
//                    struct sockaddr       ifr_netmask;
//                    struct sockaddr       ifr_hwaddr;
//                    short                 ifr_flags;
//                    int                   ifr_ifindex;
//                    int                   ifr_metric;
//                    int                   ifr_mtu;
//                    struct ifmap          ifr_map;
//                    char                  ifr_slave[IFNAMSIZ];
//                    char                  ifr_newname[IFNAMSIZ];
//                    char *                ifr_data;
//    };
//};

//struct ifconf { 
//    int ifc_len;                          /* размер буфера */
//    union {
//                    char *                ifc_buf; /* адрес буфера */ 
//                    struct ifreq *ifc_req; /* массив структур */
//    };
//};

    struct ifreq ifr;
    struct sockaddr_in dhcp_socket_address;
    size_t dhcp_packet_with_opts_buffer_size = sizeof(struct dhcp_packet_with_opts);
    //  указатель на структур  dhcp_packet
    struct dhcp_packet *current_dhcp_packet_pointer;

    struct namelist *input_interfaces_namelist = NULL;
    struct namelist *except_interfaces_namelist = NULL;
    struct namelist *dhcp_servers_namelist = NULL;

//  struct interface {
//    int index;
//    struct in_addr addr;
//    struct interface *next;
//    char name[IF_NAMESIZE];
//  };

    struct interface *ifaces = NULL;

    char *runfile = PIDFILE;
    char *user = USER;
    int debug = 0, altports = 0, demonize = 1;

    while (1) {
        int option = getopt(argc, argv, "b:e:i:s:u:r:dvpn");

        if (option == -1) {
            break;
        }

        switch (option) {
            case 's': case 'b': case 'i': case 'e': {
	        struct namelist *new_namelist = malloc(sizeof(struct namelist));

    	        if (!new_namelist) {
	            fprintf(stderr, "dhcp-helper: cannot get memory\n");
		    exit(1);
                }


// char *strncpy (char *dst, const char *src, size_t len);
//dst — указатель на буфер назначения.
//src — указатель на исходную строку.
//len — максимальное количество копируемых символов (см. раздел Безопасность ниже).
//Функция копирует из строки src в буфер dst не более чем len символов (включая нулевой символ), 
// не гарантируя завершения строки нулевым символом (если длина строки src больше или равна len). 
// Если длина строки src меньше len, то буфер добивается до len нуль- символами.
	        strncpy(new_namelist->name, optarg, IF_NAMESIZE);
	        strncpy(ifr.ifr_name, optarg, IF_NAMESIZE);
                fprintf(stderr, "[OPTIONS] ifr.ifr_name %s\n", ifr.ifr_name);


	        new_namelist->addr.s_addr = 0;

	        if (option == 's') {
	            struct hostent *e = gethostbyname(optarg);
		    if (!e) {
		        fprintf(stderr, "dhcp-helper: cannot resolve server name %s\n", optarg);
		        exit(1);
	            }
                    new_namelist->addr = *((struct in_addr *)e->h_addr);
	        } else if (strlen(optarg) > IF_NAMESIZE) {
                    fprintf(stderr, "dhcp-helper: interface name too long: %s\n", optarg);
		    exit(1);
                // fd = socket(PF_INET, SOCK_DGRAM, 0) -   создает сокет
	        } else if ((fd == -1 && (fd = socket(PF_INET, SOCK_DGRAM, 0)) == -1) ||
		    ioctl (fd, SIOCGIFFLAGS, &ifr) == -1) {
	            fprintf(stderr, "dhcp-helper: bad interface %s: %s\n", optarg, strerror(errno));
		    exit (1);
                } else if (option == 'b' && !(ifr.ifr_flags & IFF_BROADCAST)) {
		    fprintf(stderr, "dhcp-helper: interface %s cannot broadcast\n", optarg);
		    exit(1);
                }

	        if (option == 'i') {
                    new_namelist->next = input_interfaces_namelist;
		    input_interfaces_namelist = new_namelist;

	        } else if (option == 'e') {
		    new_namelist->next = except_interfaces_namelist;
		    except_interfaces_namelist = new_namelist;
	        } else {
		    new_namelist->next = dhcp_servers_namelist;
		    dhcp_servers_namelist = new_namelist;
	        }


            } //case s
            break;

            case 'u':
	        if ((user = malloc(strlen(optarg) + 1))) {
	            strcpy(user, optarg);
                }
	    break;

	    case 'r':
	        if ((runfile = malloc(strlen(optarg) + 1))) {
	            strcpy(runfile, optarg);
                }
            break;

	    case 'd':
	        debug = 1;
	    break;

            case 'p':
                altports = 1;
            break;

            case 'n':
                demonize = 0;
            break;

            case 'v':
                fprintf(stderr, "dhcp-helper version %s, %s\n", VERSION, COPYRIGHT);
	        exit(0);

	    default:
                fprintf(stderr, 
		  "Usage: dhcp-helper [OPTIONS]\n"
		  "Options are:\n"
		  "-s <server>      Forward DHCP requests to <server>\n"
		  "-b <interface>   Forward DHCP requests as broadcasts via <interface>\n"
                  "-i <interface>   Listen for DHCP requests on <interface>\n"
		  "-e <interface>   Do not listen for DHCP requests on <interface>\n"
		  "-u <user>        Change to user <user> (defaults to %s)\n"
		  "-r <file>        Write daemon PID to this file (default %s)\n"
		  "-p               Use alternative ports (1067/1068)\n"
		  "-d               Debug mode\n"
		  "-n               Do not demonize\n"
		  "-v               Give version and copyright info and then exit\n",
		  USER, PIDFILE);
                exit(1);

        } // switch
    } // while (1)


    struct namelist *tmp1;
    if (input_interfaces_namelist) {
        for (tmp1 = input_interfaces_namelist; tmp1; tmp1 = tmp1->next) {
            fprintf(stdout, "[INPUT INTERFACES] interface %s in_addr %s \n", tmp1, inet_ntoa(tmp1->addr));

        }
    }

    if (dhcp_servers_namelist) {
        for (tmp1 = dhcp_servers_namelist; tmp1; tmp1 = tmp1->next) {
            fprintf(stdout, "[DHCP SERVERS] server: %s in_addr %s \n", tmp1, inet_ntoa(tmp1->addr));
        }
    } else {
        fprintf(stdout, "dhcp-helper: no destination specifed; give at least -s or -b option.\n");
        exit(1); 
    }

    if (!(current_dhcp_packet_pointer = malloc(dhcp_packet_with_opts_buffer_size))) {
        perror("dhcp-helper: cannot allocate buffer for dhcp packet");
        exit(1);
    }

    if (fd == -1 && (fd = socket(PF_INET, SOCK_DGRAM, 0)) == -1) {
        perror("dhcp-helper: cannot create socket");
        exit(1);
    }

    if (setsockopt(fd, SOL_IP, IP_PKTINFO, &oneopt, sizeof(oneopt)) == -1 ||
        setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &oneopt, sizeof(oneopt)) == -1 ||
        setsockopt(fd, SOL_IP, IP_MTU_DISCOVER, &mtuopt, sizeof(mtuopt)) == -1) {
        perror("dhcp-helper: cannot set options on DHCP socket");
        exit(1);
    }


    dhcp_socket_address.sin_family = AF_INET;
    dhcp_socket_address.sin_port = htons(altports ? DHCP_SERVER_ALTPORT : DHCP_SERVER_PORT);
    dhcp_socket_address.sin_addr.s_addr = INADDR_ANY;

    if (bind(fd, (struct sockaddr *)&dhcp_socket_address, sizeof(struct sockaddr_in))) {
        perror("dhcp-helper: cannot bind DHCP server socket");
        exit(1);
    }

    if (!debug) {
        FILE *pidfile;
        int i;
        struct passwd *ent_pw = getpwnam(user);
        gid_t dummy;
        struct group *gp;
        cap_user_header_t hdr = malloc(sizeof(*hdr));
        cap_user_data_t data = NULL;

        if (getuid() == 0) {
            if (hdr) {
                int capsize = 1;
	        /* find version supported by kernel */
	        memset(hdr, 0, sizeof(*hdr));
	        capget(hdr, NULL);
	        if (hdr->version != LINUX_CAPABILITY_VERSION_1) {
	            /* if unknown version, use largest supported version (3) */
		    if (hdr->version != LINUX_CAPABILITY_VERSION_2)
		        hdr->version = LINUX_CAPABILITY_VERSION_3; {
                        capsize = 2;
                    }
	        }

                if ((data = malloc(sizeof(*data) * capsize))) {
		    memset(data, 0, sizeof(*data) * capsize);
                }
	    }

            if (!hdr || !data) {
                perror("dhcp-helper: cannot allocate memory");
                exit(1);
	    }

            hdr->pid = 0; /* this process */
            data->effective = data->permitted = data->inheritable = (1 << CAP_NET_ADMIN) | (1 << CAP_SETGID) | (1 << CAP_SETUID);

	     /* Tell kernel to not clear capabilities when dropping root */
	    if (capset(hdr, data) == -1 || prctl(PR_SET_KEEPCAPS, 1) == -1) {
                perror("dhcp-helper: cannot set kernel capabilities");
                exit(1);
	    }
	    if (!ent_pw) {
	        fprintf(stderr, "dhcp-helper: cannot find user %s\n", user);
	        exit(1);
	    };
	} // if (!debug)

        if (chdir("/") == -1) {
            perror("dhcp-helper: cannot change directory");
            exit(1);
	}

        if (demonize) {
	    /* The following code "daemonizes" the process.
	    See Stevens section 12.4 */
            if (fork() != 0 )
	        _exit(0);

	    setsid();

	    if (fork() != 0)
	        _exit(0);
        }

        umask(022); /* make pidfile 0644 */
            /* write pidfile _after_ forking ! */
        if ((pidfile = fopen(runfile, "w"))) {
	  fprintf(pidfile, "%d\n", (int) getpid());
	  fclose(pidfile);
        }

        umask(0);

        for (i=0; i<64; i++) {
	    if (i != fd) {
                close(i);
            }
        }

        if (getuid() == 0) {
            setgroups(0, &dummy);

            if ((gp = getgrgid(ent_pw->pw_gid))) {
	        i = setgid(gp->gr_gid);
            }
            i = setuid(ent_pw->pw_uid); 

            data->effective = data->permitted = 1 << CAP_NET_ADMIN;
            data->inheritable = 0;

            /* lose the setuid and setgid capbilities */
            capset(hdr, data);
        }
    } // while(1)

    while (1) {

        int iface_index;
        struct interface *iface;
        ssize_t message_size;
//struct msghdr {
//    void         *msg_name;       /* optional address */
//    socklen_t     msg_namelen;    /* size of address */
//    struct iovec *msg_iov;        /* scatter/gather array */
//    size_t        msg_iovlen;     /* # elements in msg_iov */
//    void         *msg_control;    /* ancillary data, see below */
//    size_t        msg_controllen; /* ancillary data buffer len */
//    int           msg_flags;      /* flags on received message */
//};
        struct msghdr msg;
//       The pointer iov points to an array of iovec structures, defined
//       in <sys/uio.h> as:
//
//           struct iovec {
//               void  *iov_base;    /* Starting address */
//               size_t iov_len;     /* Number of bytes to transfer */
//           };
        struct iovec iov;


// https://www.opennet.ru/man.shtml?topic=recvmsg&category=2&russian=0
// https://www.opennet.ru/cgi-bin/opennet/man.cgi?topic=cmsg&category=3
//       The cmsghdr structure is defined as follows:
//           struct cmsghdr {
//               size_t cmsg_len;    /* Data byte count, including header
//                                      (type is socklen_t in POSIX) */
//               int    cmsg_level;  /* Originating protocol */
//               int    cmsg_type;   /* Protocol-specific type */
//           /* followed by
//              unsigned char cmsg_data[]; */
//           };
        struct cmsghdr *cmptr;

//      struct in_pktinfo {
//              unsigned int   ipi_ifindex;  /* Interface index */
//              struct in_addr ipi_spec_dst; /* Local address */
//              struct in_addr ipi_addr;     /* Header Destination
//                                             address */
//       };
        struct in_pktinfo *pkt;


        union {
          struct cmsghdr align; /* this ensures alignment */
          char control[CMSG_SPACE(sizeof(struct in_pktinfo))];
        } control_u;

        msg.msg_control = control_u.control;
        msg.msg_controllen = sizeof(control_u);
        msg.msg_name = &dhcp_socket_address;
        msg.msg_namelen = 0;
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

        iov.iov_base = current_dhcp_packet_pointer;
        iov.iov_len = dhcp_packet_with_opts_buffer_size;


        if (all_packets_count > 1024*1024 ) {
            all_packets_count = 0;
        }


        // Этот цикл убеждается что переменная msg имеет буффер достаточного размера
        // что бы принять пакет 
        // при этом сам пакет читается но из буффера не удаляется
        //
        while (1) {
            fprintf(stderr, "[MAIN] Start\n");

            struct dhcp_packet *new_dhcp_packet_pointer;
            size_t new_dhcp_packet_with_opts_buffer_size;

            msg.msg_flags = 0;

            // http://ru.manpages.org/recvmsg/2
            // MSG_PEEK
            // Этот флаг заставляет выбрать данные из начала очереди приёма, но не удалять их оттуда.
            // Таким образом, последующий вызов вернёт те же самые данные.

            // возвращает длину сообщения в переменну message_size
            // message_size = -1 - ошибка чтения
            //
            while((message_size = recvmsg(fd, &msg, MSG_PEEK)) == -1 && errno == EINTR);

            // тут успешно прочитали пакет -> message_size != -1
            // или ошибка не была прерыванием

            all_packets_count = all_packets_count + 1;

            fprintf(stdout, "[MAIN %d] Start\n", all_packets_count);
            fprintf(stdout, "[MAIN %d] msg = %d\n", all_packets_count, msg);
            fprintf(stdout, "[MAIN %d] message_size = %d\n", all_packets_count, message_size);


            // MSG_TRUNC (начиная с Linux 2.2)
            // Для «сырых» данных (AF_PACKET), дейтаграмм Интернета (начиная с Linux 2.4.27/2.6.8),
            // netlink (начиная с Linux 2.6.22) и дейтаграмм UNIX (начиная с Linux 3.4)
            // возвращает реальную длину пакета или дейтаграммы, даже если она была больше,
            // чем предоставленный буфер.
            fprintf(stdout, "[MAIN %d] message_size = %d\n", all_packets_count, message_size);
            // message_size == -1 - ошибка чтения
            if ( message_size == -1) {
                fprintf(stdout, "[MAIN %d] message_size = %d Packet read error\n", all_packets_count, message_size);
                break;
            }

            // !(msg.msg_flags & MSG_TRUNC) - не (сообщение не влезло в буфер) т е влезло в буфер
            if ( !(msg.msg_flags & MSG_TRUNC) ) {
                fprintf(stdout, "[MAIN %d] (msg.msg_flags & MSG_TRUNC) = %lX, message is not truncated \n", all_packets_count, (msg.msg_flags & MSG_TRUNC));
                break;
            }

            // тут предпологается что сообщение не влезло в буфер
            new_dhcp_packet_with_opts_buffer_size = dhcp_packet_with_opts_buffer_size + 100;
            new_dhcp_packet_pointer = realloc(current_dhcp_packet_pointer, new_dhcp_packet_with_opts_buffer_size);
            fprintf(stdout, "[MAIN %d] new_dhcp_packet_pointer = %X\n", all_packets_count, new_dhcp_packet_pointer);
            // The C library function void *realloc(void *ptr, size_t size) attempts to resize 
            // the memory block pointed to by ptr that was previously allocated with a call to malloc or calloc.
            if  (!(new_dhcp_packet_pointer) ) {
                // не (смогли выделить большний буффер вместо имевшегося на 100 байт больше)
                fprintf(stdout, "[MAIN %d] new_dhcp_packet_pointer = %X\n", all_packets_count, new_dhcp_packet_pointer);
	        break;
            }

            // тут - сообщение успешно прочитано и влезло в буфер и смогли поресайзить область памяти на которую указывал 
            // current_dhcp_packet_pointer 
            // на следующией 
            iov.iov_base = new_dhcp_packet_pointer;
            current_dhcp_packet_pointer = new_dhcp_packet_pointer;

            //msg.msg_iov = &iov; (выше)
            // т е по факту увеличивается буффер на который ссылается msg
            iov.iov_len = new_dhcp_packet_with_opts_buffer_size;
            dhcp_packet_with_opts_buffer_size = new_dhcp_packet_with_opts_buffer_size;

            fprintf(stdout, "[MAIN %d] dhcp_packet_with_opts_buffer_size = %X\n", all_packets_count, new_dhcp_packet_with_opts_buffer_size);
        }


        // по-настоящему читаем пакет
        while ((message_size = recvmsg(fd, &msg, 0)) == -1 && errno == EINTR);

        // Если пакет все еще слишком большой то игнорируем его
        if ((msg.msg_flags & MSG_TRUNC) ||
	    message_size < (ssize_t)(sizeof(struct dhcp_packet)) ||
	    msg.msg_controllen < sizeof(struct cmsghdr)) {
            fprintf(stderr, "[MAIN %i] ((msg.msg_flags & MSG_TRUNC) || message_size < (ssize_t)(sizeof(struct dhcp_packet)) || msg.msg_controllen < sizeof(struct cmsghdr)) \n", all_packets_count);
            fprintf(stderr, "[MAIN %i] Packet is too big or not DHCP packed, ignoring\n", all_packets_count);
            continue;
        }


        iface_index = 0;
        fprintf(stderr, "[MAIN %i] msg = %lX\n", all_packets_count, &msg);

        //
        //struct cmsghdr *cmptr;
        for (cmptr = CMSG_FIRSTHDR(&msg); cmptr; cmptr = CMSG_NXTHDR(&msg, cmptr)) {
            fprintf(stderr, "[MAIN %i] cmptr = %X\n", all_packets_count, &cmptr);
            fprintf(stderr, "[MAIN %i] cmptr->cmsg_level = %d SOL_IP     = %d\n", all_packets_count, cmptr->cmsg_level, SOL_IP);
            fprintf(stderr, "[MAIN %i] cmptr->cmsg_type =  %d IP_PKTINFO = %d\n", all_packets_count, cmptr->cmsg_type, IP_PKTINFO);

            if (cmptr->cmsg_level == SOL_IP && cmptr->cmsg_type == IP_PKTINFO) {
                union {
                    unsigned char *c;
                    struct in_pktinfo *p;
                } p;
                p.c = CMSG_DATA(cmptr);
//       *  CMSG_DATA() returns a pointer to the data portion of a
//          cmsghdr.  The pointer returned cannot be assumed to be
//          suitably aligned for accessing arbitrary payload data types.
//          Applications should not cast it to a pointer type matching the
//          payload, but should instead use memcpy(3) to copy data to or
//          from a suitably declared object.

                iface_index = p.p->ipi_ifindex;

//      struct in_pktinfo {
//              unsigned int   ipi_ifindex;  /* Interface index */
//              struct in_addr ipi_spec_dst; /* Local address */
//              struct in_addr ipi_addr;     /* Header Destination
//                                             address */
//       };



            }
            fprintf(stderr, "[MAIN %i] iface_index = %d\n", all_packets_count, iface_index);
        }
// struct ifreq ifr
// https://www.opennet.ru/man.shtml?topic=netdevice&category=7&russian=0
//struct ifreq {
//    char            ifr_name[IFNAMSIZ];   /* Имя интерфейса */
//    union {
//                    struct sockaddr       ifr_addr;
//                    struct sockaddr       ifr_dstaddr;
//                    struct sockaddr       ifr_broadaddr;
//                    struct sockaddr       ifr_netmask;
//                    struct sockaddr       ifr_hwaddr;
//                    short                 ifr_flags;
//                    int                   ifr_ifindex;
//                    int                   ifr_metric;
//                    int                   ifr_mtu;
//                    struct ifmap          ifr_map;
//                    char                  ifr_slave[IFNAMSIZ];
//                    char                  ifr_newname[IFNAMSIZ];
//                    char *                ifr_data;
//    };
//};
        if (!(ifr.ifr_ifindex = iface_index) || ioctl(fd, SIOCGIFNAME, &ifr) == -1) {
            fprintf(stderr, "[MAIN %i] iface_index ifr.ifr_ifindex = iface_index) || ioctl(fd, SIOCGIFNAME, &ifr) == -1)\n", all_packets_count);
            continue;
        } else {
            fprintf(stderr, "[MAIN %i] ifr.ifr_ifname = %s\n", all_packets_count, ifr.ifr_name);
        }

        /* last ditch loop squashing. */
        fprintf(stderr, "[MAIN %i] current_dhcp_packet_pointer->hops %i \n", all_packets_count, current_dhcp_packet_pointer->hops);
        if ((current_dhcp_packet_pointer->hops++) > 20) {
            fprintf(stderr, "[MAIN %i] Hops > 20, packet is ignored %i \n", all_packets_count);
            continue;
        }

        fprintf(stderr, "[MAIN %i] current_dhcp_packet_pointer->hlen %i , DHCP_CHADDR_MAX = %i \n", all_packets_count, current_dhcp_packet_pointer->hlen, DHCP_CHADDR_MAX);
        if (current_dhcp_packet_pointer->hlen > DHCP_CHADDR_MAX) {
            fprintf(stderr, "[MAIN %i] Size is > $d (DHCP_CHADDR_MAX), packet is ignored %i \n", DHCP_CHADDR_MAX);
            continue;
        }

        if (current_dhcp_packet_pointer->op == BOOTREQUEST) {

            if (bootrequest_packets_count > 1024*1024 ) {
                bootrequest_packets_count = 0;
            }

            bootrequest_packets_count = bootrequest_packets_count + 1;
            fprintf(stderr, "[BOOTREQUEST %i] packet->op == BOOTREQUEST\n" ,bootrequest_packets_count);
            /* message from client */
            struct namelist *tmp;

            fprintf(stderr, "[BOOTREQUEST %i] IF_NAMESIZE = %d\n" ,bootrequest_packets_count, IF_NAMESIZE);

	    /* packets from networks we are broadcasting _too_ are explicitly not allowed to be forwarded _from_ */
            fprintf(stderr, "[BOOTREQUEST %i] %s\n", bootrequest_packets_count, "---- packets from networks we are broadcasting _too_ are explicitly not allowed to be forwarded _from_ ----");
            for (tmp = dhcp_servers_namelist; tmp; tmp = tmp->next) {
                fprintf(stderr, "[BOOTREQUEST %i] dhcp_servers_namelist->addr.s_addr %s \n", bootrequest_packets_count,  inet_ntoa(tmp->addr));
                fprintf(stderr, "[BOOTREQUEST %i] dhcp_servers_namelist->name %s \n", bootrequest_packets_count,  tmp->name);
                fprintf(stderr, "[BOOTREQUEST %i] ifr.ifr_name %s \n", bootrequest_packets_count,  ifr.ifr_name);

	        if (tmp->addr.s_addr == 0 && strncmp(tmp->name, ifr.ifr_name, IF_NAMESIZE) == 0) {
                    fprintf(stderr, "[BOOTREQUEST %i] dhcp_servers_namelist addr: %s ifr.ifr_name: %s  BREAK\n", bootrequest_packets_count, inet_ntoa(tmp->addr), ifr.ifr_name);
	            break;
                } else {
                    fprintf(stderr, "[BOOTREQUEST %i] (tmp->addr.s_addr == 0 && strncmp(tmp->name, ifr.ifr_name, IF_NAMESIZE) == 0) is FALSE FOR INTERFACE %s\n", bootrequest_packets_count, tmp);
                }
            } //for

	    if (tmp) {
                fprintf(stderr, "[BOOTREQUEST %i] if (tmp)  -- continue \n", bootrequest_packets_count);
	        continue;
            }
            fprintf(stderr, "[BOOTREQUEST %i] %s\n", bootrequest_packets_count, "---- packets from networks we are broadcasting _too_ are explicitly not allowed to be forwarded _from_  finish----");





            /* check if it came from an allowed interface */
            fprintf(stderr, "[BOOTREQUEST %i] %s\n", bootrequest_packets_count, "----check if it came from an allowed interface-----");
	    for (tmp = except_interfaces_namelist; tmp; tmp = tmp->next) {
                fprintf(stderr, "[BOOTREQUEST %i] except_interfaces_namelist: %s",bootrequest_packets_count,  except_interfaces_namelist);
                fprintf(stderr, "[BOOTREQUEST %i] except_interfaces_namelist->name = %s  ifr.ifr_name = %s \n", bootrequest_packets_count, tmp->name, ifr.ifr_name);
	        if (strncmp(tmp->name, ifr.ifr_name, IF_NAMESIZE) == 0) {
                    fprintf(stderr, "[BOOTREQUEST %i] except_interfaces_namelist = %s  BREAK\n", bootrequest_packets_count, tmp->name);
	            break;
                } else {
                    fprintf(stderr, "[BOOTREQUEST %i] except_interfaces_namelist interface = %s, ifr.ifr_name = %s \n", bootrequest_packets_count, tmp->name, ifr.ifr_name);

                }
            }

	    if (tmp) {
                fprintf(stderr, "[BOOTREQUEST %i] %s\n", bootrequest_packets_count, "tmp (dhcp_servers_namelist in list???) --> continue");
                continue;
            }
            fprintf(stderr, "[BOOTREQUEST %i] %s\n", bootrequest_packets_count, "----check if it came from an allowed interface finished----");




            fprintf(stderr, "[BOOTREQUEST %i] %s\n", bootrequest_packets_count, "----check input_interfaces_namelist-----");
	    if (input_interfaces_namelist) {
                fprintf(stderr, "[BOOTREQUEST %i] interfaces\n", bootrequest_packets_count);
	        for (tmp = input_interfaces_namelist; tmp; tmp = tmp->next) {
                    fprintf(stderr, "[BOOTREQUEST %i] interface %s \n",bootrequest_packets_count, tmp);
	            if (strncmp(tmp->name, ifr.ifr_name, IF_NAMESIZE) == 0) {
                        fprintf(stderr, "[BOOTREQUEST %i] interfaces->name = %s  ifr.ifr_name = %s \n", bootrequest_packets_count,  tmp->name, ifr.ifr_name);
                        fprintf(stderr, "[BOOTREQUEST %i] %s\n", bootrequest_packets_count, "strncmp(interfaces->name,  ifr.ifr_name, IF_NAMESIZE) == 0)  == TRUE,  BREAK");
		        break;
                    } else {
                        fprintf(stderr, "[BOOTREQUEST %i] input_interfaces_namelist->name = %s  ifr.ifr_name = %s \n", bootrequest_packets_count,  tmp->name, ifr.ifr_name);
                        fprintf(stderr, "[BOOTREQUEST %i] %s\n", bootrequest_packets_count, "(strncmp(input_interfaces_namelist->name, ifr.ifr_name, IF_NAMESIZE) == 0)  == FALSE");
                    }
                }

    	        if (!tmp) {
                    fprintf(stderr, "[BOOTREQUEST %i] %s\n", bootrequest_packets_count, "No one interace is met condition ifr.ifr_name in list input_interfaces_namelist --> continue\n");
	            continue;
                } else {
                    fprintf(stderr, "[BOOTREQUEST %i] Request From interface --> %s\n", bootrequest_packets_count, tmp);
                }
	    } else {
                fprintf(stderr, "[BOOTREQUEST %i] NOT input_interfaces_namelist\n", bootrequest_packets_count);
            }
            fprintf(stderr, "[BOOTREQUEST %i] %s\n", bootrequest_packets_count, "----check input_interfaces_namelist finished-----");





    	    /* already gatewayed ? */
            fprintf(stderr, "[BOOTREQUEST %i] %s\n", bootrequest_packets_count, "-----already gatewayed ?------");
	    if (current_dhcp_packet_pointer->giaddr.s_addr) {
	        /* if so check if by us, to stomp on loops. */
                fprintf(stderr, "[BOOTREQUEST %i] ifaces  %s current_dhcp_packet_pointer->giaddr.s_addr --> %d \n", bootrequest_packets_count, "if so check if by us, to stomp on loops", current_dhcp_packet_pointer->giaddr.s_addr);
	        for (iface = ifaces; iface; iface = iface->next) {
                    fprintf(stderr, "[BOOTREQUEST %i] ifaces  iface = %s\n iface->addr.s_addr --> %d current_dhcp_packet_pointer->giaddr.s_addr --> %d \n", bootrequest_packets_count ,iface, iface->addr.s_addr, current_dhcp_packet_pointer->giaddr.s_addr);
	            if (iface->addr.s_addr == current_dhcp_packet_pointer->giaddr.s_addr) {
                        fprintf(stderr, "[BOOTREQUEST %i] ifaces (iface->addr.s_addr == packet->giaddr.s_addr) == TRUE --> BREAK", bootrequest_packets_count);
		        break;
                    }
                }

	        if (iface) {
	            continue;
                }
	    } else {
                fprintf(stderr, "[BOOTREQUEST %i] %s\n", bootrequest_packets_count, "Plug in our address (no giaddr in packet)");
	        /* plug in our address */
	        struct in_addr iface_addr;
	        ifr.ifr_addr.sa_family = AF_INET;
                fprintf(stderr, "[BOOTREQUEST %i] ifr.ifr_addr.sa_family -->  %d\n", bootrequest_packets_count, ifr.ifr_addr.sa_family);
	        if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
                    fprintf(stderr, "[BOOTREQUEST %i] ioctl(fd, SIOCGIFADDR, &ifr) == -1\n", bootrequest_packets_count);
	            continue;
                }
                fprintf(stderr, "[BOOTREQUEST %i] ifr.ifr_addr -->  %d\n", bootrequest_packets_count, ifr.ifr_addr);
	        iface_addr = current_dhcp_packet_pointer->giaddr = ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr;

                fprintf(stderr, "[BOOTREQUEST %i] iface_addr (addrress where we got dhcp packet) -->  %s\n", bootrequest_packets_count, inet_ntoa(iface_addr));

	        /* build address->interface index table for returning answers */
                fprintf(stderr, "[BOOTREQUEST %i] %s\n", bootrequest_packets_count, "--build address->interface index table for returning answers--");
	        for (iface = ifaces; iface; iface = iface->next) {
                    fprintf(stderr, "[BOOTREQUEST %i] iface:  %s\n", bootrequest_packets_count, iface);
	            if (iface->addr.s_addr == iface_addr.s_addr) {
		        iface->index = iface_index;
		        break;
		    }
                }
                fprintf(stderr, "[BOOTREQUEST %i] %s\n", bootrequest_packets_count, "--build address->interface index table for returning answers finished--");


	        /* not there, add a new entry */
                fprintf(stderr, "[BOOTREQUEST %i] %s %s\n", bootrequest_packets_count, "Add a new entry" ,tmp);
	        if (!iface && (iface = malloc(sizeof(struct interface)))) {
		    iface->next = ifaces;
		    ifaces = iface;
		    iface->addr = iface_addr;
		    iface->index = iface_index;

                    fprintf(stderr, "[BOOTREQUEST %i] %s\n", bootrequest_packets_count, "Add a new entry");
	        }


            } // already gatewayed ?
            fprintf(stderr, "[BOOTREQUEST %i] %s\n", bootrequest_packets_count, "-----already gatewayed ? finished------");



            fprintf(stderr, "[BOOTREQUEST %i] %s\n", bootrequest_packets_count, "-----ifaces structure------");
	    for (iface = ifaces; iface; iface = iface->next) {
                fprintf(stderr, "[BOOTREQUEST %i] ifaces: %s iface->next: %d iface->addr  %s iface->index: %d\n",
                                bootrequest_packets_count, iface, iface->next, inet_ntoa(iface->addr), iface->index);
            }
            fprintf(stderr, "[BOOTREQUEST %i] %s\n", bootrequest_packets_count, "-----ifaces structure------");


	    /* send to all configured dhcp_servers_namelist. */
            fprintf(stderr, "[BOOTREQUEST %i] %s\n", bootrequest_packets_count, "send to all configured dhcp_servers_namelist");
	    for (tmp = dhcp_servers_namelist; tmp; tmp = tmp->next) {
	        /* Do this each time round to pick up address changes. */
                fprintf(stderr, "[BOOTREQUEST %i] %s\n", bootrequest_packets_count, "Do this each time round to pick up address changes.");
                fprintf(stderr, "[BOOTREQUEST %i] dhcp_servers_namelist: %s addr.s_addr %d\n", bootrequest_packets_count, tmp, tmp->addr.s_addr);
	        if (tmp->addr.s_addr == 0) {
                    fprintf(stderr, "[BOOTREQUEST %i] dhcp_servers_namelist: %s addr.s_addr == 0\n", bootrequest_packets_count, tmp);
		    strncpy(ifr.ifr_name, tmp->name, IF_NAMESIZE);
		    if (ioctl(fd, SIOCGIFBRDADDR, &ifr) == -1) {
                        fprintf(stderr, "[BOOTREQUEST %i] dhcp_servers_namelist: %s ioctl(fd, SIOCGIFBRDADDR, &ifr)  == -1 --> continue\n", bootrequest_packets_count, tmp);
    		        continue;
                    }
		    dhcp_socket_address.sin_addr = ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr;
                } else {
                    fprintf(stderr, "[BOOTREQUEST %i] dhcp_servers_namelist: %s addr.s_addr != 0\n", bootrequest_packets_count, tmp);
	            dhcp_socket_address.sin_addr = tmp->addr;
                }
                //fprintf(stderr, "[BOOTREQUEST %i] dhcp_servers_namelist: %s dhcp_socket_address.sin_addr %d\n", bootrequest_packets_count, dhcp_socket_address.sin_addr);

	        dhcp_socket_address.sin_port = htons(altports ? DHCP_SERVER_ALTPORT : DHCP_SERVER_PORT);

	        while(sendto(fd, current_dhcp_packet_pointer, message_size, 0, (struct sockaddr *)&dhcp_socket_address, sizeof(dhcp_socket_address)) == -1 && errno == EINTR);
	    }






        } else if (current_dhcp_packet_pointer->op == BOOTREPLY) {
            if (bootreply_packets_count > 1024*1024 ) {
                bootreply_packets_count = 0;
            }
            bootreply_packets_count = bootreply_packets_count + 1;

            fprintf(stderr, "[BOOTREPLY %i]\n", bootreply_packets_count);
            fprintf(stderr, "[BOOTREPLY %i] packet->op == BOOTREPLY\n", bootreply_packets_count);
	    /* packet from server send back to client */
            fprintf(stderr, "[BOOTREPLY %i] %s\n", bootreply_packets_count, "packet from server send back to client");
            dhcp_socket_address.sin_port = htons(altports ? DHCP_CLIENT_ALTPORT : DHCP_CLIENT_PORT);
            fprintf(stderr, "[BOOTREPLY %i] addr.sin_port =  %d\n", bootreply_packets_count, dhcp_socket_address.sin_port);
	    msg.msg_control = NULL;
	    msg.msg_controllen = 0;
    	    msg.msg_namelen = sizeof(dhcp_socket_address);
	    iov.iov_len = message_size;



    	    /* look up interface index in cache */
            fprintf(stderr, "[BOOTREPLY %i]  %s\n", bootreply_packets_count, "look up interface index in cache");
	    for (iface = ifaces; iface; iface = iface->next) {
                 fprintf(stderr, "[BOOTREPLY %i] iface =  %s\n" , bootreply_packets_count, iface);
                 fprintf(stderr, "[BOOTREPLY %i] iface->addr.s_addr =  %d\n" , bootreply_packets_count, iface->addr.s_addr);
                 fprintf(stderr, "[BOOTREPLY %i] current_dhcp_packet_pointer->giaddr.s_addr =  %d\n" , bootreply_packets_count, current_dhcp_packet_pointer->giaddr.s_addr);
            }
            fprintf(stderr, "[BOOTREQUEST %i] %s\n", bootrequest_packets_count, "-----ifaces structure------");

            fprintf(stderr, "[BOOTREPLY %i] %s\n" , bootreply_packets_count , "---look up interface index in cache---");
	    for (iface = ifaces; iface; iface = iface->next) {
                 fprintf(stderr, "[BOOTREPLY %i] iface =  %s\n" , bootreply_packets_count, iface);
                 fprintf(stderr, "[BOOTREPLY %i] iface->addr.s_addr =  %d\n" , bootreply_packets_count, iface->addr.s_addr);
                 fprintf(stderr, "[BOOTREPLY %i] current_dhcp_packet_pointer->giaddr.s_addr =  %d\n" , bootreply_packets_count, current_dhcp_packet_pointer->giaddr.s_addr);

                // giaddr -> relay Address
	        if (iface->addr.s_addr == current_dhcp_packet_pointer->giaddr.s_addr) {
                    fprintf(stderr, "[BOOTREPLY %i] current_dhcp_packet_pointer->giaddrs  %s  iface->addr %s   --> %s  \n" ,
                            bootreply_packets_count, inet_ntoa(current_dhcp_packet_pointer->giaddr), inet_ntoa(iface->addr), "break");
        	    break;
                }
            }

	    if (!iface) {
                fprintf(stderr, "[BOOTREPLY %i] (!iface) - no interface found" , bootreply_packets_count);
	        continue;
            } else {
                fprintf(stderr, "[BOOTREPLY %i] found iface =  %s \n" , bootreply_packets_count, iface);
                fprintf(stderr, "[BOOTREPLY %i] current_dhcp_packet_pointer->giaddrs  %s  iface->addr %s \n" ,
                        bootreply_packets_count, inet_ntoa(current_dhcp_packet_pointer->giaddr), inet_ntoa(iface->addr));
            }
            fprintf(stderr, "[BOOTREPLY %i] %s\n" , bootreply_packets_count , "---look up interface index in cache finished---");




            fprintf(stderr, "[BOOTREPLY %i] current_dhcp_packet_pointer->hlen    %d\n", bootreply_packets_count, current_dhcp_packet_pointer->hlen);
            fprintf(stderr, "[BOOTREPLY %i] current_dhcp_packet_pointer->flags   %d\n", bootreply_packets_count, ntohs(current_dhcp_packet_pointer->flags));
            fprintf(stderr, "[BOOTREPLY %i] current_dhcp_packet_pointer->yiaddr  %s\n", bootreply_packets_count, inet_ntoa(current_dhcp_packet_pointer->yiaddr));
            fprintf(stderr, "[BOOTREPLY %i] current_dhcp_packet_pointer->ciaddr  %d\n", bootreply_packets_count, current_dhcp_packet_pointer->ciaddr);
            fprintf(stderr, "[BOOTREPLY %i] current_dhcp_packet_pointer->chaddr  %d\n", bootreply_packets_count, current_dhcp_packet_pointer->chaddr);

            // ciaddr exist if client already have IP address
            // yiaddr offerd by server
            // giaddr relay Address
            // siaddr -server address
            //http://www.tcpipguide.com/free/t_DHCPMessageFormat.htm

	    if (current_dhcp_packet_pointer->ciaddr.s_addr) {
                fprintf(stderr, "[BOOTREPLY %i] current_dhcp_packet_pointer->ciaddr.s_addr = %d\n" , bootreply_packets_count, current_dhcp_packet_pointer->ciaddr.s_addr);
	        dhcp_socket_address.sin_addr = current_dhcp_packet_pointer->ciaddr;
	    } else if (
                ntohs(current_dhcp_packet_pointer->flags) & 0x8000 ||
                !current_dhcp_packet_pointer->yiaddr.s_addr ||
                current_dhcp_packet_pointer->hlen > 14
            ) {
                fprintf(stderr, "[BOOTREPLY %i] broadcast to 255.255.255.255\n" , bootreply_packets_count);
	        /* broadcast to 255.255.255.255 */
    	        msg.msg_controllen = sizeof(control_u);
    	        msg.msg_control = control_u.control;
    	        cmptr = CMSG_FIRSTHDR(&msg);
	        dhcp_socket_address.sin_addr.s_addr = INADDR_BROADCAST;
	        pkt = (struct in_pktinfo *)CMSG_DATA(cmptr);
	        pkt->ipi_ifindex = iface->index;
	        pkt->ipi_spec_dst.s_addr = 0;
	        msg.msg_controllen = cmptr->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
	        cmptr->cmsg_level = SOL_IP;
	        cmptr->cmsg_type = IP_PKTINFO;

	    } else {
	        /* client not configured and cannot reply to ARP.
	        Insert arp entry direct.*/
                fprintf(stderr, "[BOOTREPLY %i] Client not configured and cannot reply to ARP Insert arp entry direct.\n" , bootreply_packets_count);
	        dhcp_socket_address.sin_addr = current_dhcp_packet_pointer->yiaddr;
                fprintf(stderr, "[BOOTREPLY %i] dhcp_socket_address.sin_addr (address for client) = %s\n" ,bootreply_packets_count,  inet_ntoa(dhcp_socket_address.sin_addr));
	        ifr.ifr_ifindex = iface->index;
                fprintf(stderr, "[BOOTREPLY %i] ifr.ifr_ifinde = %d\n" ,bootreply_packets_count, iface->index);

                fprintf(stderr, "[BOOTREPLY %i] ioctl(fd, SIOCGIFNAME, &ifr) = %d\n" ,bootreply_packets_count, ioctl(fd, SIOCGIFNAME, &ifr));
	        if (ioctl(fd, SIOCGIFNAME, &ifr) != -1) {
            	    struct arpreq req;
	            struct sockaddr *pa = &req.arp_pa;
		    memcpy(pa, &dhcp_socket_address, sizeof(struct sockaddr_in));
		    req.arp_ha.sa_family = current_dhcp_packet_pointer->htype;
                    fprintf(stderr, "[BOOTREPLY %i] current_dhcp_packet_pointer->htype =  %d \n" , bootreply_packets_count, current_dhcp_packet_pointer->htype);
		    memcpy(req.arp_ha.sa_data, current_dhcp_packet_pointer->chaddr, current_dhcp_packet_pointer->hlen);
		    strncpy(req.arp_dev, ifr.ifr_name, 16);
		    req.arp_flags = ATF_COM;
                    int a;
		    a = ioctl(fd, SIOCSARP, &req);
                    fprintf(stderr, "[BOOTREPLY %i] ioctl(fd, SIOCSARP, &req); %i \n" , bootreply_packets_count, a);
	        } else {
                    fprintf(stderr, "[BOOTREPLY %i] ifr.ifr_ifinde\n" ,bootreply_packets_count);
                }
	    }
                    int status;
                    char iproute_add_command[1024];
                    status = sprintf(iproute_add_command, "/sbin/ip route replace %s dev %s", inet_ntoa(current_dhcp_packet_pointer->yiaddr), ifr.ifr_name);
//                    status = system(iproute_add_command);
                    fprintf(stderr,"[BOOTREPLY %i], iproute_add_command: %s status = %d\n",  bootreply_packets_count, iproute_add_command, status);

            fprintf(stderr, "[BOOTREPLY %i] sendmsg(fd, &msg, 0) == -1 && errno == EINTR); start\n" ,bootreply_packets_count);
	    while (sendmsg(fd, &msg, 0) == -1 && errno == EINTR);
            fprintf(stderr, "[BOOTREPLY %i] sendmsg  %d \n", msg);
            fprintf(stderr, "[BOOTREPLY %i] sendmsg(fd, &msg, 0) == -1 && errno == EINTR); finis\nh" ,bootreply_packets_count);

        } else {
            fprintf(stderr, "[UNDEFINED??] current_dhcp_packet_pointer->op %i\n", current_dhcp_packet_pointer->op);
        }
    }
}
