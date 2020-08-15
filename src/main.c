//
// Created by stalkervr on 8/8/20.
//

#include "header.h"

//int main(int argc, char** argv)
int main(int argc, char** argv) {


    pcap_if_t *interfaces,*temp;

    pcap_t *handle;  /* Дескриптор сесси */
    char* dev;  /* Устройство для сниффинга */
    char errbuf[PCAP_ERRBUF_SIZE]; /* Строка для хранения ошибок */
    struct bpf_program fp;  /* Скомпилированный фильтр */
    char filter_exp[] = "port 80"; /* Выражение фильтра */
    bpf_u_int32 mask;  /* Сетевая маска устройства */
    bpf_u_int32 net;  /* IP устройства */
    struct pcap_pkthdr header; /* Заголовок который нам дает PCAP */
    const u_char *packet;  /* Пакет */

    // show app info
    print_app_info();
    // show ip address host
    print_address();

    // выводим список доступных сетевых интерфейсов и
    // определяем устройство для захвата трафика dev
    // выбираем первое из списка доступных интерфейсов
    dev = set_default_net_interface(interfaces,temp,errbuf);
    printf("\n  Capture interface installed : %s\n", dev);

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Can't get netmask for device %s\n", dev);
        net = 0;
        mask = 0;
    } else {
        printf(" Netmask for device %u: \n",mask);
        printf(" IP device %u: \n", net);
    }

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    } else {
        printf(" Open interface : %s\n", dev);
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    } else {
        printf(" Filter parsed: %s \n", filter_exp);
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    } else {
        printf(" Installed filter: %s \n",filter_exp);
    }

    /* Захват пакета */
    packet = pcap_next(handle, &header);
    /* Вывод его длины */
    printf("Jacked a packet with length of [%d]\n", header.len);
    printf("Jacked a packet with length of [%ld]\n", header.ts.tv_sec);
    /* Закрытие сессии */
    pcap_close(handle);

    return 0;
}




