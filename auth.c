//
// Created by stalkervr on 8/22/20.
//

#include "header.h"



int main() {
    pam_handle_t* pamh;
    struct pam_conv pamc;
    /* Указание диалоговой функции. */
    pamc.conv = &misc_conv;

    pamc.appdata_ptr = NULL;
    /* Начало сеанса аутентификации. */
    pam_start("su", getenv("USER"), &pamc, &pamh);
    /* Аутентификация пользователя. */
    if (pam_authenticate(pamh, 0) != PAM_SUCCESS)
        fprintf(stderr, "Authentication failed!\n");
    else {
        fprintf(stderr, "Authentication OK.\n");
        system("su -c konsole");
    }

    /* Конец сеанса. */
    pam_end(pamh, 0);
    return 0;
}

