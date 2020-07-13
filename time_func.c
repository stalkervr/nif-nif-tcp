//
// Created by stalkervr on 7/13/20.
//
#include "header.h"

void time_local()
{
    time_t timer;
    time(&timer);
    printf ("Local time is: %s", ctime(&timer));
}

