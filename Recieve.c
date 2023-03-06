#include<stdio.h>               //For standard things
#include<stdlib.h>              //malloc
#include<string.h>              //memset
#include<netinet/ip_icmp.h>     //Provides declarations for icmp header
#include<netinet/udp.h>         //Provides declarations for udp header
#include<netinet/tcp.h>         //Provides declarations for tcp header
#include<netinet/ip.h>          //Provides declarations for ip header
#include<sys/socket.h>
#include<arpa/inet.h>
#include<unistd.h>

void processPacket(unsigned char*);
void handleMessage(unsigned char*);

int sock_raw;
// буфер для хранения сообщения
char global_buffer[1024];
// текущий размер сообщения
int global_n = 0;
char * src_addr, *dst_addr;

int main(int argc, char* argv[]) {
    if (argc < 3) {
        puts("Enter source and destination ip");
        return 1;
    }

    src_addr = argv[1];
    dst_addr = argv[2];

    int saddr_size , data_size;
    struct sockaddr saddr;

    unsigned char *buffer = (unsigned char *)malloc(65536); //Its Big!

    puts("Starting...");
    // Создание "сырого" сокета, который будет прослушивать
    sock_raw = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);
    if(sock_raw < 0)     {
        printf("Socket Error\n");
        return 1;
    }

    while(1) {
        saddr_size = sizeof saddr;
        // Получение пакета
        data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , &saddr_size);
        if(data_size <0 )
        {
            printf("Recvfrom error , failed to get packets\n");
            return 1;
        }
        // Обработка пакета
        processPacket(buffer);
    }
    close(sock_raw);
    printf("Finished");
    return 0;
}

void processPacket(unsigned char* buffer) {
    // Получение указателя на IP заголовок пакета
    struct iphdr *iph = (struct iphdr*)buffer;

    // Если получен TCP пакет
    if (iph->protocol == IPPROTO_TCP) {
        // обработка сообщения
        handleMessage(buffer);
    }
}

void handleMessage(unsigned char *Buffer) {
    int i;

    struct iphdr *iph = (struct iphdr *)Buffer;
    struct tcphdr *tcph = (struct tcphdr *) (Buffer + sizeof (struct iphdr));

    struct sockaddr_in source,dest;
    // получение адресов цели и источника
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
    // если адрес источника совпадает с требуемым
    if (source.sin_addr.s_addr == inet_addr(src_addr)
            && dest.sin_addr.s_addr == inet_addr(dst_addr)) {
        // выбор потока вывода
        setvbuf (stdout, NULL, _IONBF, 0);
        // массив с полезной нагрузкой
        char payload[6];
        // извлечение первой часли полезной нагрузки
        payload[0] = iph->id >> 8;
        payload[1] = iph->id & ((1 << 8) - 1);
        //извлечение второй части полезной нагрузки
        for (i = 0; i < 4; ++i) {
            payload[i + 2] = (tcph->seq >> i*8) & ((1 << 8 ) - 1);
        }
        // копирование глобальный буфер
        for (i = 0; i < 6; ++i) {
            global_buffer[global_n++] = payload[i];
        }
        // вывод полученной части сообщения
        for (i = 0; i < 6; ++i) {
            // проверка на окончание
            if (payload[i])
                printf("%c", payload[i]);
            else {
                // 0 => конец сообщения
                // перенос строки
                puts("");
                // сброс текущей длины сообщения
                global_n = 0;
                // выход из цикла
                break;
            }
        }
    }
}
