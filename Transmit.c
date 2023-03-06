#include<stdio.h>           //for printf
#include<string.h>          //memset
#include<sys/socket.h>      //for socket ofcourse
#include<stdlib.h>          //for exit(0);
#include<errno.h>           //For errno - the error number
#include<netinet/tcp.h>     //Provides declarations for tcp header
#include<netinet/ip.h>      //Provides declarations for ip header
#include<unistd.h>
#include<arpa/inet.h>
#include<stdlib.h>
#include<time.h>

// 96 бит (12 байт) псевдо-заголовок, нужный для вычисления хэш-суммы
struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

// функция вычисление хэш-суммы
unsigned short csum(unsigned short *ptr,int nbytes) {
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;

    return(answer);
}

int main (int argc, char* argv[]) {
    srand(time(NULL));

    if (argc < 3) {
        puts("Enter source and destination ip");
        return 1;
    }

    while (1) {
        puts("Enter payload:");
        char payload[1024];
        // считывание строки
        fgets(payload, 1024, stdin);
        // получение длины строки
        int length = strlen(payload);
        // нуль-терминирование строки
        if (length > 0 && payload[strlen (payload) - 1] == '\n')
            payload[strlen (payload) - 1] = '\0';
        // завершение при отсутствии полезной нагрузки
        if (!length)
            break;

        // вычисление необходимого количества пакетов
        int n = (length + 5)/6;

        int i;
        for (i = 0; i < n; ++i) {
            // задержка между отправлением пакетов
            usleep(10000);
            // Создание сокета в RAW режиме
            int s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);

            if(s == -1) {
                // Создание сокета закончилось ошибкой
                // вероятно, из-за отсутствия привилегий
                perror("Failed to create socket");
                exit(1);
            }

            // побитовове представление пакета
            char datagram[4096] , source_ip[32] , *pseudogram;

            // инициализация нулями
            memset (datagram, 0, 4096);

            // IP заголовок
            struct iphdr *iph = (struct iphdr *) datagram;

            //TCP заголовок
            struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct iphdr));
            struct sockaddr_in sin;
            struct pseudo_header psh;

            //some address resolution
            strcpy(source_ip , argv[1]);
            sin.sin_family = AF_INET;
            sin.sin_port = htons(80);
            sin.sin_addr.s_addr = inet_addr (argv[2]);

            // Заполнение IP заголовка
            // Минимальная корректная длина 5
            iph->ihl = 5;
            // IPv3
            iph->version = 4;
            // приоритет не важен
            iph->tos = 0;
            // вычисление общей длины пакета
            iph->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr);
            // первая часть полезной нагрузки
            iph->id = (6*i < length ? payload[6*i] << 8 : 0)
                    + (6*i + 1 < length ? payload[6*i + 1] : 0);
            // Если id == 0, он заменяется на случайное значение, что нам не выгодно
            // При присвоении ему единицы, первая половина останется нулевой,
            // что соответствует концу строки
            if (iph->id == 0)
                iph->id = 1;
            // Первый фрагмент => нулевое смещение
            iph->frag_off = 0;
            // Стандартный во многих случаях TTL
            iph->ttl = 64;
            // Протокол TCP
            iph->protocol = IPPROTO_TCP;
            // Выставление нуля перед вычислением хэш-суммы
            iph->check = 0;
            // Исходящий IP
            iph->saddr = inet_addr ( source_ip );
            // IP точки назначения
            iph->daddr = sin.sin_addr.s_addr;

            // Вычисление хэша IP заголовка
            iph->check = csum ((unsigned short *) datagram, iph->tot_len);

            // Заголовок TCP
            // порт источника
            tcph->source = htons (20);
            // порт цели
            tcph->dest = htons (rand() % 10000); // "сканируем" разные порты
            tcph->ack_seq = 0;

            // Вторая часть полезной нагрузки
            tcph->seq = 0;
            int j;
            for (j = 0; j < 4; ++j)
                tcph->seq += (6*i + 2 + j < length ? payload[6*i + 2 + j] : 0) << 8*j;

            // сдвиг равен размеру заголовка
            tcph->doff = 5;
            // Из флагов интересует только SYN
            tcph->fin=0;
            tcph->syn=1;
            tcph->rst=0;
            tcph->psh=0;
            tcph->ack=0;
            tcph->urg=0;
            // максимальный размер окна
            tcph->window = htons (5840);
            // хэш-сумма будет заполнена при помощи псевдо-заголовка
            tcph->check = 0;
            // нулевая "важность"
            tcph->urg_ptr = 0;

            // Подготовка к вычислению хэша
            psh.source_address = inet_addr( source_ip );
            psh.dest_address = sin.sin_addr.s_addr;
            psh.placeholder = 0;
            psh.protocol = IPPROTO_TCP;
            psh.tcp_length = 0;

            int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
            pseudogram = (char*)malloc(psize);

            memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
            memcpy(pseudogram + sizeof(struct pseudo_header) , tcph,
                   sizeof(struct tcphdr));
            tcph->check = csum( (unsigned short*) pseudogram , psize);

            free(pseudogram);

            //IP_HDRINCL чтобы сказать ядру, что заголовки включены в пакет
            int one = 1;
            const int *val = &one;

            if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
            {
                perror("Error setting IP_HDRINCL");
                exit(0);
            }
            // Отправка пакета
            if (sendto (s, datagram, iph->tot_len ,  0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
            {
                perror("sendto failed");
            }
            // Успех
            else
            {
                // информация об отправленном пакете
                printf ("Packet sent. \"" );
                for (j = 0; j < 6; ++j)
                    if (6*i + j < length)
                    printf("%c", payload[6*i + j]);
                puts("\"");
            }
        }
    }

    return 0;
}
