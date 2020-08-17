//
// Created by stalkervr on 8/8/20.
//

#include "header.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void print_payload(const u_char *payload, int len);

void print_hex_ascii_line(const u_char *payload, int len, int offset);

int main(int argc, char** argv)
{

    pcap_if_t *interfaces,*temp;

    char* dev;                              // Устройство для сниффинга
    char errbuf[PCAP_ERRBUF_SIZE];          // Строка для хранения ошибок
    pcap_t *handle;                         // Дескриптор сессии

    char* filter_exp = argv[2];             // Выражение фильтра
    struct bpf_program fp;                  // Скомпилированный фильтр
    bpf_u_int32 mask;                       // Сетевая маска устройства
    bpf_u_int32 net;                        // IP устройства
    //struct pcap_pkthdr header;              // Заголовок который нам дает PCAP
    //const u_char *packet;                   // Пакет
    char def_int[] = DEFAULT_NET_INTERFACE; // сетевой интерфейс по умолчанию
    int num_packets = -1;                   // количество пакетов для захвата отрицат ч-ло -> не ограничено

    // показать информацию о программе
    print_app_info();
    // показать ip адрес хоста
    print_address();


    // выводим список доступных сетевых интерфейсов и
    // определяем устройство для захвата трафика dev
    // если указан параметр -def
    // выбираем первое из списка доступных интерфейсов
    if (strcmp(argv[1],def_int) == 0)
    {
        dev = set_default_net_interface(interfaces,temp,errbuf);
        //printf("\n Capture interface installed : %s\n", dev);
    } else {
        dev = argv[1];
    }

    // определяем сетевую маску и IP устройства
    // необходимо для фильтра
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, " Can't get netmask for device %s\n", dev);
        net = 0;
        mask = 0;
    } else {
        //printf(" Netmask for device %u: \n",mask);
        //printf(" IP device %u: \n", net);
    }

    // открываем сессию захвата трафика
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, " Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    } else {
        //printf(" Open interface : %s\n", dev);
    }

    // проверяем, что мы захватываем на устройстве Ethernet
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "%s is not an Ethernet\n", dev);
        exit(EXIT_FAILURE);
    }

    // компилируем фильтр трафика из переданного в коммандной строке выржения
    // второй параметр в строке
    // если фильтр не указан используется фильтр по умолчанию
    if(argc < 3)
    {
        filter_exp = DEFAULT_FILTER_EXPRESSION;
    }
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, " Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    } else {
        //printf(" Filter parsed: %s \n", filter_exp);
    }

    if(argc > 3)
    {
        fprintf(stderr, " Error: unrecognized command-line options\n\n");
        print_app_usage();
        exit(EXIT_FAILURE);
    }

    // устанавливаем фильтр трафика
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, " Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    } else {
        //printf(" Installed filter: %s \n",filter_exp);
    }

    // вывод информации о настройках сниффинга
    print_capture_info(dev,mask,net,num_packets,filter_exp);

    /* Захват пакета */
    //packet = pcap_next(handle, &header);
    /* Вывод его длины */
    //printf("\n");
    //printf(" Jacked a packet with length of [%d]\n", header.len);
    //printf(" Jacked a packet with length of [%ld]\n", header.ts.tv_sec);

    pcap_loop(handle, num_packets, got_packet, NULL);

    /* Закрытие сессии */
    /* cleanup */
    pcap_freecode(&fp);
    pcap_close(handle);

    printf("\nCapture complete.\n");

    return 0;
}

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void print_hex_ascii_line(const u_char *payload, int len, int offset)
{
    int i;
    int gap;
    const u_char *ch;

    /* offset */
    printf("%05d   ", offset);

    /* hex */
    ch = payload;
    for(i = 0; i < len; i++) {
        printf("%02x ", *ch);
        ch++;
        /* print extra space after 8th byte for visual aid */
        if (i == 7)
            printf(" ");
    }
    /* print space to handle line less than 8 bytes */
    if (len < 8)
        printf(" ");

    /* fill hex gap with spaces if not full line */
    if (len < 16) {
        gap = 16 - len;
        for (i = 0; i < gap; i++) {
            printf("   ");
        }
    }
    printf("   ");

    /* ascii (if printable) */
    ch = payload;
    for(i = 0; i < len; i++) {
        if (isprint(*ch))
            printf("%c", *ch);
        else
            printf(".");
        ch++;
    }

    printf("\n");

    return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void print_payload(const u_char *payload, int len)
{
    int len_rem = len;
    int line_width = 16;			/* number of bytes per line */
    int line_len;
    int offset = 0;					/* zero-based offset counter */
    const u_char *ch = payload;

    if (len <= 0)
        return;

    /* data fits on one line */
    if (len <= line_width) {
        print_hex_ascii_line(ch, len, offset);
        return;
    }

    /* data spans multiple lines */
    for ( ;; ) {
        /* compute current line length */
        line_len = line_width % len_rem;
        /* print line */
        print_hex_ascii_line(ch, line_len, offset);
        /* compute total remaining */
        len_rem = len_rem - line_len;
        /* shift pointer to remaining bytes to print */
        ch = ch + line_len;
        /* add offset */
        offset = offset + line_width;
        /* check if we have line width chars or less */
        if (len_rem <= line_width) {
            /* print last line and get out */
            print_hex_ascii_line(ch, len_rem, offset);
            break;
        }
    }

    return;
}

/*
 * dissect/print packet
 */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    static int count = 1;                   /* packet counter */

    /* declare pointers to packet headers */
    const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
    const struct sniff_ip *ip;              /* The IP header */
    const struct sniff_tcp *tcp;            /* The TCP header */
    const char *payload;                    /* Packet payload */

    int size_ip;
    int size_tcp;
    int size_payload;

    printf("\nPacket number %d:\n", count);
    count++;

    /* define ethernet header */
    ethernet = (struct sniff_ethernet*)(packet);

    /* define/compute ip header offset */
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }

    /* print source and destination IP addresses */
    printf("       From: %s\n", inet_ntoa(ip->ip_src));
    printf("         To: %s\n", inet_ntoa(ip->ip_dst));

    /* определение протокола значения определены в netinet/in.h*/
    switch(ip->ip_p) {
        case IPPROTO_IP:
            /* Dummy protocol for TCP.  */
            printf("   Protocol: IP\n");
            return;
        case IPPROTO_ICMP:
            /* Internet Control Message Protocol.  */
            printf("   Protocol: ICMP\n");
            return;
        case IPPROTO_IGMP:
            /* Internet Group Management Protocol. */
            printf("   Protocol: IGMP\n");
            return;
        case IPPROTO_IPIP:
            /* IPIP tunnels (older KA9Q tunnels use 94).  */
            printf("   Protocol: IPIP\n");
            return;
        case IPPROTO_TCP:
            // Transmission Control Protocol.
            printf("   Protocol: TCP\n");
            break;
        case IPPROTO_EGP:
            /* Exterior Gateway Protocol.  */
            printf("   Protocol: EGP\n");
            break;
        case IPPROTO_PUP:
            /* PUP protocol.  */
            printf("   Protocol: PUP\n");
            break;
        case IPPROTO_UDP:
            // User Datagram Protocol.
            printf("   Protocol: UDP\n");
            return;
        case IPPROTO_IDP:
            /* XNS IDP protocol.  */
            printf("   Protocol: IDP\n");
            break;
        case IPPROTO_TP:
            /* SO Transport Protocol Class 4.  */
            printf("   Protocol: TP\n");
            break;
        case IPPROTO_DCCP:
            /* Datagram Congestion Control Protocol.  */
            printf("   Protocol: DCCP\n");
            break;
        case IPPROTO_IPV6:
            /* IPv6 header.  */
            printf("   Protocol: IPV6\n");
            break;
        case IPPROTO_RSVP:
            /* Reservation Protocol.  */
            printf("   Protocol: RSVP\n");
            break;
        case IPPROTO_GRE:
            /* General Routing Encapsulation.  */
            printf("   Protocol: GRE\n");
            break;
        case IPPROTO_ESP:
            /* encapsulating security payload.  */
            printf("   Protocol: ESP\n");
            break;
        case IPPROTO_AH:
            /* authentication header.  */
            printf("   Protocol: AH\n");
            break;
        case IPPROTO_MTP:
            /* Multicast Transport Protocol.  */
            printf("   Protocol: MTP\n");
            break;
        case IPPROTO_BEETPH:
            /* IP option pseudo header for BEET.  */
            printf("   Protocol: BEETPH\n");
            break;
        case IPPROTO_ENCAP:
            /* Encapsulation Header.  */
            printf("   Protocol: ENCAP\n");
            break;
        case IPPROTO_PIM:
            /* Protocol Independent Multicast.  */
            printf("   Protocol: PIM\n");
            break;
        case IPPROTO_COMP:
            /* Compression Header Protocol.  */
            printf("   Protocol: COMP\n");
            break;
        case IPPROTO_SCTP:
            /* Stream Control Transmission Protocol.  */
            printf("   Protocol: SCTP\n");
            break;
        case IPPROTO_UDPLITE:
            /* UDP-Lite protocol.  */
            printf("   Protocol: UDPLITE\n");
            break;
        case IPPROTO_MPLS:
            /* MPLS in IP.  */
            printf("   Protocol: MPLS\n");
            break;
        case IPPROTO_RAW:
            /* Raw IP packets.  */
            printf("   Protocol: RAW\n");
            break;

        default:
            printf("   Protocol: unknown\n");
            return;
    }

    /*
     *  OK, this packet is TCP.
     */

    /* define/compute tcp header offset */
    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp)*4;
    if (size_tcp < 20) {
        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return;
    }

    printf("   Src port: %d\n", ntohs(tcp->th_sport));
    printf("   Dst port: %d\n", ntohs(tcp->th_dport));

    /* define/compute tcp payload (segment) offset */
    payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

    /* compute tcp payload (segment) size */
    size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

    /*
     * Print payload data; it might be binary, so don't just
     * treat it as a string.
     */
    if (size_payload > 0) {
        printf("   Payload (%d bytes):\n", size_payload);
        print_payload(payload, size_payload);
    }

    return;
}




