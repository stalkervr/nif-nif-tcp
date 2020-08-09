//
// Created by stalkervr on 7/7/20.
//

#ifndef NIF_NIF_TCP_HEADER_H
#define NIF_NIF_TCP_HEADER_H

// system lib connect
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>


#include <time.h>
#include <netdb.h>
#include <ifaddrs.h>

#define APP_NAME		"nifnif"
#define APP_DESC		"Sniffer example using libpcap"
#define APP_COPYRIGHT	"Copyright (c) 2020 STALKERVR"
#define APP_DISCLAIMER	"THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM."


//
void print_app_info();
//


// time_func
void time_local();
//

// ip address check
struct ifaddrs *addresses;
void print_address();
//

#endif //NIF_NIF_TCP_HEADER_H

