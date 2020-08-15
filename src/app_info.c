//
// Created by stalkervr on 8/8/20.
//

#include "header.h"

void print_app_info(){
    printf("\n");
    printf(" %s - %s\n", APP_NAME, APP_DESC);
    printf(" %s\n", APP_COPYRIGHT);
    printf(" %s\n", APP_DISCLAIMER);
    time_local();
    printf("\n");
}

void print_app_usage()
{
    printf(" Usage: %s [interface] [filter expression]\n", APP_NAME);
    printf("\n");
    printf(" Options:\n");
    printf("    interface            Listen on <interface> for packets.\n");
    printf("                         set -def for using default interface.\n");
    printf("    filter expression    \"host 140.82.118.3\" as example.\n");
    printf("\n");
}

void print_capture_info(
        char* dev, bpf_u_int32 mask, bpf_u_int32 net, int num_packets, char* filter_exp)
{
    printf("\n");
    printf(" Device:             %s\n", dev);
    printf(" Netmask for device: %u\n", mask);
    printf(" IP device:          %u\n", net);
    if(num_packets < 0){
        printf(" Number of packets:  unlimited\n");
    } else {
        printf(" Number of packets: %d\n", num_packets);
    }
    printf(" Filter expression:  %s\n", filter_exp);
}