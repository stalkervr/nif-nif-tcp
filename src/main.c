//
// Created by stalkervr on 8/8/20.
//

#include "header.h"

int main(int argc, char** argv) {
    // show local host time
    time_local();
    // show ip address host
    print_address();
    print_app_info();

    char error[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces,*temp;
    int i=0;
    if(pcap_findalldevs(&interfaces,error)==-1)
    {
        printf("\n Error in pcap findall devs");
        return -1;
    }

    printf("\n The interfaces present on the system are:");
    for(temp=interfaces;temp;temp=temp->next)
    {
        printf("\n %d  :  %s",i++,temp->name);

    }
    // устройство для захвата трафика dev
    // выбираем первое из списка доступных интерфейсов

    char* dev = interfaces->name;
    printf("\n Default interface : %s\n", dev);


    pcap_t *handle;

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, error);
    if (handle == NULL)
    {
        fprintf(stderr, " Couldn't open device %s: %s\n", dev, error);
        return(2);
    } else {
        printf(" Open interface : %s\n", dev);
    }

    printf("%s",system("host 140.82.118.3"));

    return 0;
}




