//
// Created by stalkervr on 9/2/20.
//
#include "header.h"

void write_log() {

    char log_name[100] = {0};
    strcat(log_name,"log/");
    strcat(log_name, time_rec());
    strcat(log_name,".json");
    system("cp live_scan.json log/live_scan.json");
    rename("log/live_scan.json", log_name);
    //system("rm live_scan.json ");
}