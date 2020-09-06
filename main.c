//
// Created by stalkervr on 8/8/20.
//
// подключаем общий заголовок
#include "header.h"
//

// глобальные переменные
int  num_packets = 0;
//

int main(int argc, char** argv)
{
    pcap_if_t *interfaces = NULL;
    pcap_if_t *temp = NULL;

    char* dev;                             // Устройство для сниффинга
    char errbuf[PCAP_ERRBUF_SIZE];         // Строка для хранения ошибок
    pcap_t *handle;                        // Дескриптор сессии

    char* filter_exp = argv[2];            // Выражение фильтра
    struct bpf_program fp;                 // Скомпилированный фильтр
    bpf_u_int32 mask;                      // Сетевая маска устройства
    bpf_u_int32 net;                       // IP устройства
    struct pcap_pkthdr header;           // Заголовок который нам дает PCAP
    const u_char *packet;                // Пакет
    char* def_int = DEFAULT_NET_INTERFACE; // сетевой интерфейс по умолчанию
    num_packets = 20;                       // количество пакетов для захвата отрицат ч-ло -> не ограничено

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
    handle = pcap_open_live(dev, BUFSIZ, 1, 100, errbuf);
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
    // проверяем количество переданных аргументов
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

    //server();

    //int temp_s = server();

    /*while(temp_s < 0){
        temp_s=server();
        server();
    }*/

    /* Захват пакета */
    //packet = pcap_next(handle, &header);
    /* Вывод его длины */
    //printf("\n");
    //printf(" Jacked a packet with length of [%d]\n", header.len);
    //printf(" Jacked a packet with length of [%ld]\n", header.ts.tv_sec);

    pcap_loop(handle, num_packets, got_packet, NULL);

    write_log();

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
    //const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
    //const struct sniff_tcp *tcp;            /* The TCP header */
    //const char *payload;                    /* Packet payload */

    //int size_ip;
    //int size_tcp;

    int time = header->ts.tv_sec;
    int size_payload;
    sendMes temp_str[num_packets];

    printf("\nPacket number : %d\n", count);
    temp_str[count-1].pac_num = count;
    printf("\nTime sec : %d\n", time);
    temp_str[count-1].time = time;

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
    strcpy(temp_str[count-2].source_ip, inet_ntoa(ip->ip_src));

    printf("         To: %s\n", inet_ntoa(ip->ip_dst));
    strcpy(temp_str[count-2].dest_ip,inet_ntoa(ip->ip_dst));

    /* определение протокола значения определены в netinet/in.h*/
    switch(ip->ip_p) {
        case IPPROTO_IP:
            /* Dummy protocol for TCP.  */
            printf("   Protocol: IP\n");
            strcpy(temp_str[count-2].protocol, "IP");
            return;
        case IPPROTO_ICMP:
            /* Internet Control Message Protocol.  */
            printf("   Protocol: ICMP\n");
            strcpy(temp_str[count-2].protocol, "ICMP");
            return;
        case IPPROTO_IGMP:
            /* Internet Group Management Protocol. */
            printf("   Protocol: IGMP\n");
            strcpy(temp_str[count-2].protocol, "IGMP");
            return;
        case IPPROTO_IPIP:
            /* IPIP tunnels (older KA9Q tunnels use 94).  */
            printf("   Protocol: IPIP\n");
            strcpy(temp_str[count-2].protocol, "IPIP");
            return;
        case IPPROTO_TCP:
            // Transmission Control Protocol.
            printf("   Protocol: TCP\n");
            strcpy(temp_str[count-2].protocol, "TCP");
            break;
        case IPPROTO_EGP:
            /* Exterior Gateway Protocol.  */
            printf("   Protocol: EGP\n");
            strcpy(temp_str[count-2].protocol, "EGP");
            break;
        case IPPROTO_PUP:
            /* PUP protocol.  */
            printf("   Protocol: PUP\n");
            strcpy(temp_str[count-2].protocol, "PUP");
            break;
        case IPPROTO_UDP:
            // User Datagram Protocol.
            printf("   Protocol: UDP\n");
            strcpy(temp_str[count-2].protocol, "UDP");
            return;
        case IPPROTO_IDP:
            /* XNS IDP protocol.  */
            printf("   Protocol: IDP\n");
            strcpy(temp_str[count-2].protocol, "IDP");
            break;
        case IPPROTO_TP:
            /* SO Transport Protocol Class 4.  */
            printf("   Protocol: TP\n");
            strcpy(temp_str[count-2].protocol, "TP");
            break;
        case IPPROTO_DCCP:
            /* Datagram Congestion Control Protocol.  */
            printf("   Protocol: DCCP\n");
            strcpy(temp_str[count-2].protocol, "DCCP");
            break;
        case IPPROTO_IPV6:
            /* IPv6 header.  */
            printf("   Protocol: IPV6\n");
            strcpy(temp_str[count-2].protocol, "IPV6");
            break;
        case IPPROTO_RSVP:
            /* Reservation Protocol.  */
            printf("   Protocol: RSVP\n");
            strcpy(temp_str[count-2].protocol, "RSVP");
            break;
        case IPPROTO_GRE:
            /* General Routing Encapsulation.  */
            printf("   Protocol: GRE\n");
            strcpy(temp_str[count-2].protocol, "GRE");
            break;
        case IPPROTO_ESP:
            /* encapsulating security payload.  */
            printf("   Protocol: ESP\n");
            strcpy(temp_str[count-2].protocol, "ESP");
            break;
        case IPPROTO_AH:
            /* authentication header.  */
            printf("   Protocol: AH\n");
            strcpy(temp_str[count-2].protocol, "AH");
            break;
        case IPPROTO_MTP:
            /* Multicast Transport Protocol.  */
            printf("   Protocol: MTP\n");
            strcpy(temp_str[count-2].protocol, "MTP");
            break;
        case IPPROTO_BEETPH:
            /* IP option pseudo header for BEET.  */
            printf("   Protocol: BEETPH\n");
            strcpy(temp_str[count-2].protocol, "BEETPH");
            break;
        case IPPROTO_ENCAP:
            /* Encapsulation Header.  */
            printf("   Protocol: ENCAP\n");
            strcpy(temp_str[count-2].protocol, "ENCAP");
            break;
        case IPPROTO_PIM:
            /* Protocol Independent Multicast.  */
            printf("   Protocol: PIM\n");
            strcpy(temp_str[count-2].protocol, "PIM");
            break;
        case IPPROTO_COMP:
            /* Compression Header Protocol.  */
            printf("   Protocol: COMP\n");
            strcpy(temp_str[count-2].protocol, "COMP");
            break;
        case IPPROTO_SCTP:
            /* Stream Control Transmission Protocol.  */
            printf("   Protocol: SCTP\n");
            strcpy(temp_str[count-2].protocol, "SCTP");
            break;
        case IPPROTO_UDPLITE:
            /* UDP-Lite protocol.  */
            printf("   Protocol: UDPLITE\n");
            strcpy(temp_str[count-2].protocol, "UDPLITE");
            break;
        case IPPROTO_MPLS:
            /* MPLS in IP.  */
            printf("   Protocol: MPLS\n");
            strcpy(temp_str[count-2].protocol, "MPLS");
            break;
        case IPPROTO_RAW:
            /* Raw IP packets.  */
            printf("   Protocol: RAW\n");
            strcpy(temp_str[count-2].protocol, "RAW");
            break;

        default:
            printf("   Protocol: unknown\n");
            strcpy(temp_str[count-2].protocol, "unknown");
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
    temp_str[count-2].source_port = ntohs(tcp->th_sport);
    printf("   Dst port: %d\n", ntohs(tcp->th_dport));
    temp_str[count-2].dest_port = ntohs(tcp->th_dport);

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



// file_2

    FILE* file_stream;
    if((file_stream= fopen(LIVE_SCAN_FILE, "w")) == NULL)
    {
        perror("Error occured while opening file");
        fprintf(stdout,"Error open file");
        //return 1;
    }

    const char* last_char;
    const char* json_header = "{\n\"data\": [\n";
    const char* json_footer = "\n}";

    fprintf(file_stream,"%s",json_header);

    for(int i = 0; i < (count-1); i++) {

        fprintf(file_stream,"{\"pack_number\":%d,", temp_str[i].pac_num);
        fprintf(file_stream,"\"pack_time\":%d,", temp_str[i].time);
        fprintf(file_stream, "\"source_ip\":\"%s\",", temp_str[i].source_ip);
        fprintf(file_stream,"\"dest_ip\":\"%s\",", temp_str[i].dest_ip);
        fprintf(file_stream,"\"source_port\":%d,", temp_str[i].source_port);
        fprintf(file_stream,"\"dest_port\":%d,", temp_str[i].dest_port);
        fprintf(file_stream,"\"protocol\":\"%s\"}", temp_str[i].protocol);
        if ((count-2) == i) {
            last_char = "";
        } else {
            last_char = ",";
        }
        fprintf(file_stream, "%s\n", last_char);
    }

    if ((count-1) == num_packets){
        fprintf(file_stream, "],\n\"scan_state\":%d", LIVE_SCAN_END);
    } else {
        fprintf(file_stream, "],\n\"scan_state\":%d", LIVE_SCAN_RUN);
    }
    fprintf(file_stream,"%s",json_footer);
    fclose(file_stream);
    //sleep(2);
    //*****************************************************************

//    for(int i = 0; i < (count-1); i++){
//        fprintf(stdout,"*********************************************\n");
//        fprintf(stdout,"pac_num = %d\n",temp_str[i].pac_num);
//        fprintf(stdout,"*********************************************\n");
//    }
    //*****************************************************************
    return;
}



// server

// server




