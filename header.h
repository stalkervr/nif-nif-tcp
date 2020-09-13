//
// Created by stalkervr on 8/8/20.
//

#ifndef NIF_NIF_TCP_HEADER_H
#define NIF_NIF_TCP_HEADER_H

// подключение системных бибблиотек
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
#include <stdlib.h>
#include <ctype.h>

#include <time.h>
#include <netdb.h>
#include <ifaddrs.h>

__BEGIN_DECLS
// информация о приложении
#define APP_NAME		"nifnif"
#define APP_DESC		"Sniffer example using libpcap"
#define APP_COPYRIGHT	"Copyright (c) 2020 STALKERVR"
#define APP_DISCLAIMER	"THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM."
// параметры работы по умолчанию
// использовать сетевой интерфейс по умолчанию
#define DEFAULT_NET_INTERFACE "-def"
// фильтр по умолчанию
#define DEFAULT_FILTER_EXPRESSION "ip"
// default snap length (maximum bytes per packet to capture)
#define SNAP_LEN 1518
// Заголовки Ethernet всегда состоят из 14 байтов
#define SIZE_ETHERNET 14
// Ethernet адреса состоят из 6 байт
#define ETHER_ADDR_LEN 6
// файл для записи текущего сканирования
#define LIVE_SCAN_FILE "live_scan.json"
#define LIVE_SCAN_RUN 1
#define LIVE_SCAN_END 0
__END_DECLS

// определение типа u_char
typedef unsigned char u_char;
// Заголовок Ethernet
struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Адрес назначения */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Адрес источника */
    u_short ether_type; /* IP? ARP? RARP? и т.д. */
};

// заголовок IP
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

// определение типа tcp_seq
typedef u_int tcp_seq;
// заголовок TCP
struct sniff_tcp {
    u_short th_sport; // порт источника
    u_short th_dport; // порт назначения
    tcp_seq th_seq;   // номер последовательности
    tcp_seq th_ack;   // номер подтверждения
    u_char th_offx2;  // смещение данных, rsvd
    u_short th_win;   // окно
    u_short th_sum;   // контрольная сумма
    u_short th_urp;   // экстренный указатель
    u_char th_flags;
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)

#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
};

struct pcap_rmtauth *auth;

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
// функции захвата пакетов

//

// time_func
void time_local();
char* time_rec();
//
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void print_payload(const u_char *payload, int len);
void print_hex_ascii_line(const u_char *payload, int len, int offset);
// запись логов
void write_log();
//

// ip address check
struct ifaddrs *addresses;
void print_address();
char* set_default_net_interface(pcap_if_t* interfaces, pcap_if_t* temp, char* errbuf);
//

// authentication
//sudo apt-get install libpam0g-dev
//gcc -o auth auth.c -lpam -lpam_misc
#include <security/pam_appl.h>
#include <security/pam_misc.h>
//int auth();
// authentication

// server
#include <unistd.h>
#define SERVER_PORT    "8001"
#define MAX_CONNECTION 1000
#define WEB_ROOT "/web"
#define BUFSIZ_ 8192

// перечисление типа запроса http
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
    eHTTPMethod type; // метод GET и тд
    char        path[255]; // тело запроса
}sHTTPHeader;

typedef struct {
    int   pac_num;
    int   time;
    char source_ip[100];
    char dest_ip[100];
    int   source_port;
    int   dest_port;
    char protocol[10];
} sendMes;

void *get_client_addr(struct sockaddr *);
int create_socket(const char* server_port);
// читаем соединение разбираем http
// aSock идентификатор сокета клиента
void read_http_request(int client_socket, sendMes mess_pac);
// функция разбирает запрос http
// получает строку запроса и указатель на структуру sHTTPHeader
void parse_http_request(const char*, sHTTPHeader *);
void parse_http_request_1(const char*, sHTTPHeader*);
// отправка сообщения клиенту
void send_message(int client_socket, const char* message_for_send);
void send_message_pac(int client_socket, const sendMes pack);
void send_404(int client_socket);
int server();
//
int send_net(int conn, char *buffer, size_t size);
void parse_html_http(int conn, char *filename);
// server

#endif //NIF_NIF_TCP_HEADER_H

