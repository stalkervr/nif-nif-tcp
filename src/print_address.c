//
// Created by stalkervr on 8/8/20.
//

#include "header.h"


void print_address(){


    if (getifaddrs(&addresses) == -1) {
        printf("getifaddrs call failed\n");
        //return -1;
    }

    struct ifaddrs *address = addresses;
    printf(" The addresses system:\n");
    while(address) {
        if (address->ifa_addr == NULL) {
            address = address->ifa_next;
            continue;
        }
        int family = address->ifa_addr->sa_family;
        if (family == AF_INET || family == AF_INET6) {

            printf(" %s\t", address->ifa_name);
            printf(" %s\t", family == AF_INET ? "IPv4" : "IPv6");

            char ap[100];
            const int family_size = family == AF_INET ?
                                    sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
            getnameinfo(address->ifa_addr,
                        family_size, ap, sizeof(ap), 0, 0, NI_NUMERICHOST);
            printf("\t%s\n", ap);

        }
        address = address->ifa_next;
    }

    freeifaddrs(addresses);
}

char* set_default_net_interface(pcap_if_t* interfaces, pcap_if_t* temp, char* errbuf)
{
    if(pcap_findalldevs(&interfaces, errbuf) == -1)
    {
        printf("\n Error in pcap findall devs");
        //return -1;
    }
    printf("\n The interfaces present on the system are:");
    int i = 0;
    for(temp = interfaces; temp; temp = temp->next)
    {
        printf("\n %d  :  %s", i++, temp->name);
    }
    printf("\n");

    char* dev = interfaces->name;

    return dev;
}


