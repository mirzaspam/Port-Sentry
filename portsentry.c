/*
 * PortSentry - TCP Port Scanner
 * OS Lab Project | CS225L | BSCYS Semester 4
 * Concepts: Sockets, Threads (pthreads), File I/O, Process System Calls
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <netdb.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

/* ─── Configuration ─────────────────────────────────────────── */
#define MAX_THREADS     100
#define TIMEOUT_SEC     1
#define MAX_OPEN        1024
#define BANNER_LEN      128

/* ─── ANSI Colors ────────────────────────────────────────────── */
#define GRN  "\033[0;32m"
#define RED  "\033[0;31m"
#define CYN  "\033[0;36m"
#define YEL  "\033[0;33m"
#define BLD  "\033[1m"
#define RST  "\033[0m"

/* ─── Data Structures ────────────────────────────────────────── */
typedef struct {
    int port;
    char service[32];
    char banner[BANNER_LEN];
    int open;
} PortResult;

typedef struct {
    int start_port;
    int end_port;
    char target_ip[64];
    int timeout;
} ScanTask;

/* ─── Globals ────────────────────────────────────────────────── */
PortResult  open_ports[MAX_OPEN];
int         open_count = 0;
pthread_mutex_t result_mutex = PTHREAD_MUTEX_INITIALIZER;

int         g_start, g_end;
char        g_ip[64];
pthread_mutex_t port_mutex = PTHREAD_MUTEX_INITIALIZER;
int         next_port;

/* ─── Service Name Lookup ────────────────────────────────────── */
const char* service_name(int port) {
    switch (port) {
        case 21:   return "FTP";
        case 22:   return "SSH";
        case 23:   return "Telnet";
        case 25:   return "SMTP";
        case 53:   return "DNS";
        case 67:   return "DHCP";
        case 80:   return "HTTP";
        case 110:  return "POP3";
        case 119:  return "NNTP";
        case 123:  return "NTP";
        case 135:  return "RPC";
        case 139:  return "NetBIOS";
        case 143:  return "IMAP";
        case 161:  return "SNMP";
        case 194:  return "IRC";
        case 389:  return "LDAP";
        case 443:  return "HTTPS";
        case 445:  return "SMB";
        case 465:  return "SMTPS";
        case 514:  return "Syslog";
        case 587:  return "SMTP-Sub";
        case 636:  return "LDAPS";
        case 993:  return "IMAPS";
        case 995:  return "POP3S";
        case 1433: return "MSSQL";
        case 1521: return "Oracle";
        case 3306: return "MySQL";
        case 3389: return "RDP";
        case 5432: return "PostgreSQL";
        case 5900: return "VNC";
        case 6379: return "Redis";
        case 8080: return "HTTP-Alt";
        case 8443: return "HTTPS-Alt";
        case 27017: return "MongoDB";
        default:   return "Unknown";
    }
}

/* ─── Banner Grab ────────────────────────────────────────────── */
void grab_banner(int sockfd, char *banner) {
    struct timeval tv = {1, 0};
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    int n = recv(sockfd, banner, BANNER_LEN - 1, 0);
    if (n > 0) {
        banner[n] = '\0';
        /* strip newlines */
        for (int i = 0; banner[i]; i++)
            if (banner[i] == '\n' || banner[i] == '\r') { banner[i] = '\0'; break; }
    } else {
        strcpy(banner, "-");
    }
}

/* ─── Scan One Port ──────────────────────────────────────────── */
int scan_port(const char *ip, int port, char *banner) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return 0;

    struct timeval tv = {TIMEOUT_SEC, 0};
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);

    int result = connect(sockfd, (struct sockaddr*)&addr, sizeof(addr));
    if (result == 0) {
        grab_banner(sockfd, banner);
        close(sockfd);
        return 1;
    }
    close(sockfd);
    return 0;
}

/* ─── Worker Thread ──────────────────────────────────────────── */
void* worker(void *arg) {
    (void)arg;
    while (1) {
        int port;
        pthread_mutex_lock(&port_mutex);
        if (next_port > g_end) {
            pthread_mutex_unlock(&port_mutex);
            break;
        }
        port = next_port++;
        pthread_mutex_unlock(&port_mutex);

        char banner[BANNER_LEN] = "-";
        if (scan_port(g_ip, port, banner)) {
            pthread_mutex_lock(&result_mutex);
            if (open_count < MAX_OPEN) {
                open_ports[open_count].port = port;
                open_ports[open_count].open = 1;
                strncpy(open_ports[open_count].service, service_name(port), 31);
                strncpy(open_ports[open_count].banner,  banner, BANNER_LEN - 1);
                open_count++;
                /* Live print */
                printf(GRN "  [OPEN]  " RST "%-6d  %-12s  %s\n",
                       port, service_name(port), banner);
            }
            pthread_mutex_unlock(&result_mutex);
        }
    }
    return NULL;
}

/* ─── Resolve Hostname ───────────────────────────────────────── */
int resolve(const char *host, char *ip_out) {
    struct hostent *he = gethostbyname(host);
    if (!he) return 0;
    strcpy(ip_out, inet_ntoa(*(struct in_addr*)he->h_addr));
    return 1;
}

/* ─── Save Results ───────────────────────────────────────────── */
void save_results(const char *target, int start, int end, double elapsed) {
    char fname[64];
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    strftime(fname, sizeof(fname), "scan_%Y%m%d_%H%M%S.txt", t);

    FILE *f = fopen(fname, "w");
    if (!f) { printf(RED "  [!] Could not save results.\n" RST); return; }

    fprintf(f, "PortSentry Scan Report\n");
    fprintf(f, "======================\n");
    fprintf(f, "Target   : %s\n", target);
    fprintf(f, "Range    : %d - %d\n", start, end);
    fprintf(f, "Duration : %.2f seconds\n", elapsed);
    fprintf(f, "Open     : %d port(s)\n\n", open_count);
    fprintf(f, "%-8s %-14s %s\n", "PORT", "SERVICE", "BANNER");
    fprintf(f, "-------- -------------- ------------------------\n");
    for (int i = 0; i < open_count; i++)
        fprintf(f, "%-8d %-14s %s\n",
                open_ports[i].port, open_ports[i].service, open_ports[i].banner);

    fclose(f);
    printf(CYN "\n  [+] Results saved to: %s\n" RST, fname);
}

/* ─── ASCII Banner ───────────────────────────────────────────── */
void print_banner() {
    printf(CYN BLD);
    printf("\n  ██████╗  ██████╗ ██████╗ ████████╗    \n");
    printf("  ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝    \n");
    printf("  ██████╔╝██║   ██║██████╔╝   ██║       \n");
    printf("  ██╔═══╝ ██║   ██║██╔══██╗   ██║       \n");
    printf("  ██║     ╚██████╔╝██║  ██║   ██║       \n");
    printf("  ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝       \n");
    printf(RST);
    printf(YEL "  PortSentry — TCP Port Scanner\n");
    printf("  OS Lab Project | CS225L | BSCYS Sem 4\n" RST);
    printf("  ─────────────────────────────────────\n\n");
}

/* ─── Main ───────────────────────────────────────────────────── */
int main() {
    print_banner();

    char host[128];
    int  start_port, end_port, num_threads;

    /* Input */
    printf(BLD "  Target (IP or hostname): " RST);
    scanf("%127s", host);

    printf(BLD "  Start port [1]:          " RST);
    if (scanf("%d", &start_port) != 1) start_port = 1;

    printf(BLD "  End port   [1024]:       " RST);
    if (scanf("%d", &end_port) != 1) end_port = 1024;

    printf(BLD "  Threads    [50]:         " RST);
    if (scanf("%d", &num_threads) != 1) num_threads = 50;

    /* Clamp */
    if (start_port < 1)     start_port = 1;
    if (end_port > 65535)   end_port   = 65535;
    if (num_threads < 1)    num_threads = 1;
    if (num_threads > MAX_THREADS) num_threads = MAX_THREADS;

    /* Resolve */
    char resolved_ip[64];
    if (!resolve(host, resolved_ip)) {
        printf(RED "\n  [!] Could not resolve: %s\n" RST, host);
        return 1;
    }

    printf(CYN "\n  [*] Target   : %s (%s)\n", host, resolved_ip);
    printf("  [*] Range    : %d - %d\n", start_port, end_port);
    printf("  [*] Threads  : %d\n" RST, num_threads);
    printf("\n  %-8s %-12s  %s\n", "STATE", "PORT", "SERVICE / BANNER");
    printf("  ──────────────────────────────────────────\n");

    /* Setup globals */
    strncpy(g_ip, resolved_ip, 63);
    g_start    = start_port;
    g_end      = end_port;
    next_port  = start_port;
    open_count = 0;

    /* Launch threads */
    struct timeval t1, t2;
    gettimeofday(&t1, NULL);

    pthread_t threads[MAX_THREADS];
    for (int i = 0; i < num_threads; i++)
        pthread_create(&threads[i], NULL, worker, NULL);
    for (int i = 0; i < num_threads; i++)
        pthread_join(threads[i], NULL);

    gettimeofday(&t2, NULL);
    double elapsed = (t2.tv_sec - t1.tv_sec) + (t2.tv_usec - t1.tv_usec) / 1e6;

    /* Summary */
    printf("\n  ──────────────────────────────────────────\n");
    printf(BLD "  Scan complete in %.2fs\n" RST, elapsed);
    printf(GRN "  Open ports : %d\n" RST, open_count);
    printf("  Scanned    : %d ports\n", end_port - start_port + 1);

    /* Save */
    char save;
    printf(YEL "\n  Save results to file? (y/n): " RST);
    scanf(" %c", &save);
    if (save == 'y' || save == 'Y')
        save_results(host, start_port, end_port, elapsed);

    printf("\n");
    return 0;
}
