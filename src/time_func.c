//
// Created by stalkervr on 8/8/20.
//

#include "header.h"

void time_local()
{
    printf("\n");
    time_t timer;
    time(&timer);
    printf (" Locals time is: %s", ctime(&timer));
}

