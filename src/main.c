//
// Created by stalkervr on 8/8/20.
//

#include "header.h"


int main(int argc, char** argv)
{

    pcap_if_t *interfaces,*temp;
    pcap_t *handle;                         // Дескриптор сессии
    char* dev;                              // Устройство для сниффинга
    char errbuf[PCAP_ERRBUF_SIZE];          // Строка для хранения ошибок
    struct bpf_program fp;                  // Скомпилированный фильтр
    char* filter_exp = argv[2];             // Выражение фильтра
    bpf_u_int32 mask;                       // Сетевая маска устройства
    bpf_u_int32 net;                        // IP устройства
    struct pcap_pkthdr header;              // Заголовок который нам дает PCAP
    const u_char *packet;                   // Пакет
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
    packet = pcap_next(handle, &header);
    /* Вывод его длины */
    printf("\n");
    printf(" Jacked a packet with length of [%d]\n", header.len);
    printf(" Jacked a packet with length of [%ld]\n", header.ts.tv_sec);
    /* Закрытие сессии */
    pcap_close(handle);

    return 0;
}




