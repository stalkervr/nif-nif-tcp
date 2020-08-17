//
// Created by stalkervr on 8/8/20.
//

#ifndef NIF_NIF_TCP_HEADER_H
#define NIF_NIF_TCP_HEADER_H

// system lib connect
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h> 
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <string.h>
#include <ctype.h>


#include <time.h>
#include <netdb.h>
#include <ifaddrs.h>

#define APP_NAME		"nifnif"
#define APP_DESC		"Sniffer example using libpcap"
#define APP_COPYRIGHT	"Copyright (c) 2020 STALKERVR"
#define APP_DISCLAIMER	"THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM."

//__BEGIN_DECLS
// параметры работы по умолчанию
// использовать сетевой интерфейс по умолчанию
#define DEFAULT_NET_INTERFACE "-def"
// фильтр по умолчанию
#define DEFAULT_FILTER_EXPRESSION "ip"

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* Заголовки Ethernet всегда состоят из 14 байтов */
#define SIZE_ETHERNET 14

/* Ethernet адреса состоят из 6 байт */
#define ETHER_ADDR_LEN 6
//__END_DECLS

typedef unsigned char u_char;
/* Заголовок Ethernet */
struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN ]; /* Адрес назначения */
    u_char ether_shost[ETHER_ADDR_LEN ]; /* Адрес источника */
    u_short ether_type; /* IP? ARP? RARP? и т.д. */
};

/* IP header */
struct sniff_ip {
    u_char ip_vhl;  /* версия << 4 | длина заголовка >> 2 */
    u_char ip_tos;  /* тип службы */
    u_short ip_len;  /* общая длина */
    u_short ip_id;  /* идентефикатор */
    u_short ip_off;  /* поле фрагмента смещения */
#define IP_RF 0x8000  /* reserved флаг фрагмента */
#define IP_DF 0x4000  /* dont флаг фрагмента */
#define IP_MF 0x2000  /* more флаг фрагмента */
#define IP_OFFMASK 0x1fff /* маска для битов фрагмента */
    u_char ip_ttl;  /* время жизни */
    u_char ip_p;  /* протокол */
    u_short ip_sum;  /* контрольная сумма */
    struct in_addr ip_src,ip_dst; /* адрес источника и адрес назначения */
};
#define IP_HL(ip)  (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)  (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
    u_short th_sport; /* порт источника */
    u_short th_dport; /* порт назначения */
    tcp_seq th_seq;  /* номер последовательности */
    tcp_seq th_ack;  /* номер подтверждения */
    u_char th_offx2; /* смещение данных, rsvd */
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;  /* окно */
    u_short th_sum;  /* контрольная сумма */
    u_short th_urp;  /* экстренный указатель */
};


/* declare pointers to packet headers */
const struct sniff_ethernet *ethernet; /* Заголовок Ethernet */
const struct sniff_ip *ip; /* Заголовок IP */
const struct sniff_tcp *tcp; /* Заголовок TCP */
const u_char *payload; /* Данные пакета */

u_int size_ip;
u_int size_tcp;


// app info function
void print_app_info();
void print_app_usage();
void print_capture_info(
        char* dev, bpf_u_int32 mask, bpf_u_int32 net, int num_packets, char* filter_exp);
//

// time_func
void time_local();
//

// ip address check
struct ifaddrs *addresses;
void print_address();
char* set_default_net_interface(pcap_if_t* interfaces, pcap_if_t* temp, char* errbuf);
//

// server
#define SERVER_PORT    "8001"
#define MAX_CONNECTION 1000

typedef enum
{
    eHTTP_UNKNOWN = 0
    ,eHTTP_CONNECT
    ,eHTTP_DELETE
    ,eHTTP_GET
    ,eHTTP_HEAD
    ,eHTTP_OPTIONS
    ,eHTTP_PATCH
    ,eHTTP_POST
    ,eHTTP_PUT
    ,eHTTP_TRACE
}eHTTPMethod;

typedef struct
{
    eHTTPMethod type;
    char        path[255];
}sHTTPHeader;

void *get_client_addr(struct sockaddr *);
int create_socket(const char *);

void http_request(int);
void parse_http_request(const char*, sHTTPHeader *);
void send_message(int, const char*);
void send_404(int);
int server();
//

#endif //NIF_NIF_TCP_HEADER_H

