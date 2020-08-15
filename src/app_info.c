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