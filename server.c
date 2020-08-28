//
// Created by stalkervr on 8/17/20.
//

/*
Client
    socket()
  ? bind()    ?
    connect()
    ----------------
    write()   | read()
    send()    | recv()
    sendto()  | recvfrom()
    writev()  | readv()
    sendmsg() | recvmsg()
    ----------------
    close()
Server
    socket()
    bind()
    listen()
    accept()
    ----------------
    write()   | read()
    send()    | recv()
    sendto()  | recvfrom()
    writev()  | readv()
    sendmsg() | recvmsg()
    ----------------
    close()
*/



//#include <zconf.h>

#include "header.h"

int main()
{
    // дескриптор сокета
    int sock;
    // создаем сокет на заданном порту
    sock = create_socket(SERVER_PORT);
    if(sock < 0)
    {
        fprintf(stderr, "error create socket\n");
        return -1;
    }
    // если удачно сервер запускается
    printf("server created!\n");
    // структура для хранения адреса клиента
    struct sockaddr_storage client_addr;
    // дескриптор клиента -- идентификатор сокета
    int client_d;
    // бесконечный цикл ожидающий соединения
    while(1)
    {
        socklen_t s_size = sizeof(client_addr);
        // здесь выполнение программы останавливается ожидая входящее соединение
        client_d = accept(sock, (struct sockaddr*)&client_addr, &s_size);

        if(client_d == -1)
        {
            fprintf(stderr, "error accept\n");
            return -1;
        }
        // после установки соединения браузер отправляет GET запрос и ожидает ответа
        // GET /index.html HTTP/1.1
        char ip_s[INET6_ADDRSTRLEN];
        /* extern const char *inet_ntop(int __af, const void *__cp, char *__buf, socklen_t __len)
        Convert a Internet address in binary network format for interface
        type AF in buffer starting at CP to presentation form and place
        result in buffer of length LEN astarting at BUF
         */
        inet_ntop(client_addr.ss_family, get_client_addr((struct sockaddr *)&client_addr), ip_s, sizeof ip_s);
        printf("server: got connection from %s\n", ip_s);

        // читаем соединение разбираем http
        http_request(client_d);

        close(client_d);
        /* устанавливаем параметры сокета
         * это необходимо для корректного перезапуска сервера, освобождения сокета,
         * сокет может быть переиспользован*/
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
    }

    return 0;
}
// проверяем семейство адресов и приводим к нужному типу IPv4 или IPv6
void *get_client_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET)
    {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

// функция создает новый сокет
int create_socket(const char *apstrPort)
{
    // addrinfo hetdb.h хранит всю информацию об адресе
    struct addrinfo hints;
    struct addrinfo *servinfo;
    struct addrinfo *p;
    // заполняем hints нулями
    memset(&hints, 0, sizeof(hints));

    // заполняем структуру hints IPv4 или IPv6
    hints.ai_family   = AF_UNSPEC; // не важно IPv4 или IPv6
    hints.ai_socktype = SOCK_STREAM; // тип сокета tcp stream socket
    hints.ai_flags    = AI_PASSIVE; // ip адрес заполняется автоматически

    // &servinfo выходной параметр будет заполнен внутри ф-ии
    int rez = getaddrinfo(NULL, apstrPort, &hints, &servinfo);
    if( rez != 0)
    {
        fprintf(stderr, "error getaddrinfo()\n");
        return -1;
    }

    int sock;
    int yes;
    // перебираем адреса в servinfo(это список)
    for(p = servinfo; p != NULL; p = p->ai_next)
    {
        // создаем сокет socket возвращает номер дескриптора (идентифицирующее сокет)
        sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        // если создать не удалось переходим на следующую итерацию цикла
        if(sock == -1)
            continue;
        /* устанавливаем параметры сокета
         * это необходимо для корректного перезапуска сервера, освобождения сокета,
         * сокет может быть переиспользован*/
        if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
        {
            fprintf(stderr, "error setsockopt\n");
            // закрываем сокет
            close(sock);
            // очищаем память servinfo
            freeaddrinfo(servinfo);
            return -2;
        }
        // привязываем созданный сокет к локальному адресу и порту
        if(bind(sock, p->ai_addr, p->ai_addrlen) == -1)
        {
            close(sock);
            continue;
        }
        break;
    }
    // очищаем память servinfo
    freeaddrinfo(servinfo);
    // если прошли по всему списку servinfo и не нашли нужный нам сокет
    if(p == NULL)
    {
        // если прошли по всему списку servinfo и не нашли нужный нам сокет
        fprintf(stderr, "failed to find address\n");
        return -3;
    }
    // listen подготавливает сокет для входящего соединения
    // сокет переключается в пассивный режим и ожидает соединения
    //TODO: это блокирующий сокет !!! посмотреть неблокирующий
    if(listen(sock, MAX_CONNECTION) == -1)
    {
        fprintf(stderr, "error listen\n");
        return -4;
    }

    return sock;
}
// читаем соединение разбираем http
// aSock идентификатор сокета клиента
void http_request(int aSock)
{
    const int request_buffer_size = 65536;
    char      request[request_buffer_size];

    int bytes_recvd = recv(aSock, request, request_buffer_size - 1, 0);

    if (bytes_recvd < 0)
    {
        fprintf(stderr, "error recv\n");
        return;
    }
    request[bytes_recvd] = '\0';

    printf("request:\n%s\n",request);

    sHTTPHeader req;
    parse_http_request(request, &req);

    if(req.type == eHTTP_GET)
    {
        send_message(aSock, "sensor 1: 10<br> sensor 2: 20<br><a href=\"http://cppprosto.blogspot.com/2017/09/blog-post_23.html\">external</a><br><a href=\"internal\">internal</a>");
    }
    else
    {
        send_404(aSock);
    }
}

void parse_http_request(const char *apstrRequest, sHTTPHeader *apHeader)
{
    int  type_length;
    char type[255]   = {0};
    int  index = 0;

    apHeader->type = eHTTP_UNKNOWN;

    sscanf(&apstrRequest[index], "%s", type);
    type_length = (int)strlen(type);

    if(type_length == 3)
    {
        if(type[0] == 'G' && type[1] == 'E' && type[2] == 'T')
            apHeader->type = eHTTP_GET;

        index += type_length + 1;
        sscanf(&apstrRequest[index], "%s", apHeader->path);
    }
}

void send_message(int aSock, const char *apstrMessage)
{
    char buffer[65536] = { 0 };

    strcat(buffer, "HTTP/1.1 200 OK\n\n");
    strcat(buffer, "<h1>");
    strcat(buffer, apstrMessage);
    strcat(buffer, "</h1>");

    int len = (int)strlen(buffer);
    send(aSock, buffer, len, 0);
}

void send_404(int aSock)
{
    const char *buffer = "HTTP/1.1 404 \n\n";
    int len = (int)strlen(buffer);
    send(aSock, buffer, len, 0);
}

// server: got connection from 127.0.0.1
// request:
// GET /index.html HTTP/1.1
// Host: localhost:3490
// Connection: keep-alive
// Upgrade-Insecure-Requests: 1
// User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/68.0.3440.75 Chrome/68.0.3440.75 Safari/537.36
// Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
// Accept-Encoding: gzip, deflate, br
// Accept-Language: en-US,en;q=0.9,ru;q=0.8






