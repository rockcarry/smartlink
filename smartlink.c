#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include "smartlink.h"

#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#define socklen_t int
#define get_tick_count GetTickCount
#define usleep(t) Sleep((t) / 1000)
#else
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
static uint32_t get_tick_count(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}
#endif

#define CONFIG_SEND_HOSTADP_MODE 1
#define MAX_DATA_UNIT_SIZE  39

typedef struct {
    #define TXFLAG_EXIT  (1 << 0)
    #define TXFLAG_SEND  (1 << 1)
    uint32_t  flags;
    char      netdev[16];
    uint8_t   databuf[1 + MAX_DATA_UNIT_SIZE + 2]; // 1byte len + MAX_DATA_UNIT_SIZE + 2bytes checksum
    pthread_t pthread;
    int       interval;
} SMARTLINKTX;

static int get_dev_ip(char *dev, struct in_addr *addr)
{
#ifdef WIN32
    char name[MAXBYTE];
    struct hostent *host = NULL;
    gethostname(name, MAXBYTE);
    host = gethostbyname(name);
    if (host) addr->s_addr = host->h_addr_list[0] ? *(u_long*)host->h_addr_list[0] : 0;
#else
    struct ifreq ifr = {};
    int          sock;
    strncpy(ifr.ifr_name, dev, sizeof(ifr.ifr_name));
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;
    ioctl(sock, SIOCGIFADDR, &ifr);
    close(sock);
    *addr = ((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr;
#endif
    return 0;
}

static void calculate_checksum(uint8_t *buf, int len, uint8_t *cs0, uint8_t *cs1)
{
    uint16_t checksum = 0, i;
    for (i=0; i<len; i++) checksum += buf[i];
    *cs0 = (uint8_t)(checksum >> 0);
    *cs1 = (uint8_t)(checksum >> 8);
}

static void* smartlinktx_thread_proc(void *argv)
{
    SMARTLINKTX *tx = (SMARTLINKTX*)argv;
    struct sockaddr_in dstaddr;
    int     udpfd, sendlen, datalen, opt, idx = 0;
    uint8_t buf[1472] = {0}; // udp max frame size is 1472

    udpfd = socket(AF_INET, SOCK_DGRAM, 0);
#ifdef WIN32
    opt = 1; ioctlsocket(udpfd, FIONBIO, (void*)&opt);
#else
    fcntl(udpfd, F_SETFL, fcntl(udpfd, F_GETFL, 0) | O_NONBLOCK);  // setup non-block io mode
#endif

    opt = 1; setsockopt(udpfd, SOL_SOCKET, SO_BROADCAST, (char*)&opt, sizeof(opt));
    get_dev_ip(tx->netdev, &dstaddr.sin_addr);
    dstaddr.sin_family       = AF_INET;
    dstaddr.sin_addr.s_addr |= 0xFF << 24;
    printf("broadcast ip: %s\n", inet_ntoa(dstaddr.sin_addr)); fflush(stdout);

    while (!(tx->flags & TXFLAG_EXIT)) {
        if (!(tx->flags & TXFLAG_SEND)) { usleep(100*1000); continue; }

        sendlen = ((idx * 2 + 0) << 4) | ((tx->databuf[idx] >> 0) & 0xF);
        dstaddr.sin_port = 1 + rand() % 0xFFFE;
        sendto(udpfd, buf, sendlen, 0, (struct sockaddr*)&dstaddr, (socklen_t)sizeof(dstaddr));
        printf("idx: %2d, broadcast sendlen0: %03X\n", idx, sendlen); fflush(stdout);

        sendlen = ((idx * 2 + 1) << 4) | ((tx->databuf[idx] >> 4) & 0xF);
        dstaddr.sin_port = 1 + rand() % 0xFFFE;
        sendto(udpfd, buf, sendlen, 0, (struct sockaddr*)&dstaddr, (socklen_t)sizeof(dstaddr));
        printf("idx: %2d, broadcast sendlen1: %03X\n", idx, sendlen); fflush(stdout);

        datalen = 1 + tx->databuf[0] + 2;
        idx++; idx %= datalen;
        usleep(tx->interval * 1000);
    }

    if (udpfd > 0) close(udpfd);
    return NULL;
}

void* smartlinktx_init(char *dev)
{
    SMARTLINKTX *tx = NULL;

#ifdef WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("WSAStartup failed !\n"); fflush(stdout);
        return NULL;
    }
#endif

    tx = calloc(1, sizeof(SMARTLINKTX));
    if (!tx) return NULL;

    strncpy(tx->netdev, dev, sizeof(tx->netdev));
    pthread_create(&tx->pthread, NULL, smartlinktx_thread_proc, tx);
    return tx;
}

void smartlinktx_exit(void *ctx)
{
    SMARTLINKTX *tx = (SMARTLINKTX*)ctx;
    if (!ctx) return;
    tx->flags |= TXFLAG_EXIT;
    pthread_join(tx->pthread, NULL);
    free(tx);
#ifdef WIN32
    WSACleanup();
#endif
}

void smartlinktx_send(void *ctx, uint8_t *buf, int len, int interval)
{
    SMARTLINKTX *tx = (SMARTLINKTX*)ctx;
    if (!ctx) return;
    if (buf == NULL || len == 0) { // stop data send
        tx->flags &= ~TXFLAG_SEND;
    } else { // start data send
        tx->databuf[0] = (uint8_t)(len < MAX_DATA_UNIT_SIZE ? len : MAX_DATA_UNIT_SIZE);
        memcpy(tx->databuf + 1, buf, tx->databuf[0]);
        calculate_checksum(tx->databuf, tx->databuf[0] + 1, tx->databuf + tx->databuf[0] + 1, tx->databuf + tx->databuf[0] + 2);
        tx->interval = interval ? interval : 100;
        tx->flags   |= TXFLAG_SEND;
        if (1) {
            int i;
            for (i=0; i<1+tx->databuf[0]+2; i++) printf("%02X ", tx->databuf[i]);
            printf("\n"); fflush(stdout);
        }
    }
}

typedef struct {
    uint32_t counter;
    uint8_t  mac[6];
    uint8_t  dat[1 + MAX_DATA_UNIT_SIZE + 2];
} MACDATITEM;

typedef struct {
    #define RXFLAG_EXIT         (1 << 0)
    #define RXFLAG_SCAN_CHANNEL (1 << 1)
    uint32_t   flags;
    char       netdev[16];
    uint8_t    sniffe_mac[6];
    int32_t    sniffe_chnl;
    uint32_t   sniffe_tick0;
    uint32_t   sniffe_tick1;
    int32_t    sniffe_tmin;
    int32_t    sniffe_tmax;
    #define MAX_MACDATITEM_NUM 256
    MACDATITEM macdatlist[MAX_MACDATITEM_NUM];
    pthread_t  pthread;
    PFN_SMARTLINK_CALLBCK callback;
} SMARTLINKRX;

static const uint8_t s_mac_00[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
static const uint8_t s_mac_ff[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
static int get_item_by_mac(MACDATITEM *list, int size, uint8_t *mac)
{
    uint32_t i, min, idx, found;
    for (min=0xFFFFFFFF,idx=0,found=0,i=0; (int)i<size; i++) {
        if (list[i].counter < min) {
            idx = i; min = list[i].counter;
        }
        if (memcmp(list[i].mac, s_mac_00, sizeof(list[i].mac)) == 0) {
            idx = i; break;
        }
        if (memcmp(list[i].mac, mac, sizeof(list[i].mac)) == 0) {
            idx = i; found = 1; break;
        }
    }
    memcpy(list[idx].mac, mac, sizeof(list[idx].mac));
    if (!found) list[idx].counter = 0;
    return idx;
}

static void* smartlinkrx_thread_proc(void *argv)
{
#ifndef WIN32
#if CONFIG_SEND_HOSTADP_MODE
    #define WIFI_80211_RAW_HDR_LEN (0x4E - 2)
#else
    #define WIFI_80211_RAW_HDR_LEN (0x4E - 0)
#endif
    SMARTLINKRX *rx = (SMARTLINKRX*)argv;
    int      rawfd, ret, skip, len, idx, change, item, i;
    uint8_t  mask, code, checksum0, checksum1, *rxdat;
    uint8_t  buf[1472]; // udp max frame size is 1472
    char     cmd[256 ];

    rawfd = socket(PF_PACKET, SOCK_RAW, htons(0x0003)); // ETH_P_IP - 0x0800, ETH_P_ALL - 0x0003
    if (1) {
        struct ifreq ifr = {};
        strncpy(ifr.ifr_name, rx->netdev, sizeof(ifr.ifr_name));
        setsockopt(rawfd, SOL_SOCKET, SO_BINDTODEVICE, (char*)&ifr, sizeof(ifr));
    }
    if (1) {
        struct timeval tv = { 0, 500 * 1000 }; int opt;
        setsockopt(rawfd, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv));
        opt = 16 * 1024; setsockopt(rawfd, SOL_SOCKET, SO_RCVBUF, (char*)&opt, sizeof(opt));
    }

    while (!(rx->flags & RXFLAG_EXIT)) {
        if (!rx->callback) { usleep(100*1000); continue; }

        if ((rx->flags & RXFLAG_SCAN_CHANNEL) && ((int32_t)get_tick_count() - (int32_t)rx->sniffe_tick0 > 0 || (int32_t)get_tick_count() - (int32_t)rx->sniffe_tick1 > 0)) {
//          memset(rx->macdatlist, 0, sizeof(rx->macdatlist));
            rx->sniffe_tick0 = get_tick_count() + rx->sniffe_tmin;
            rx->sniffe_tick1 = get_tick_count() + rx->sniffe_tmax;
            if (++rx->sniffe_chnl == 14) rx->sniffe_chnl = 1;
            snprintf(cmd, sizeof(cmd), "iwconfig %s channel %d", rx->netdev, rx->sniffe_chnl); system(cmd);
            printf("%s\n", cmd); fflush(stdout);
        }

        ret = recvfrom(rawfd, buf, sizeof(buf), 0, NULL, NULL);
        if (ret < 4) continue;
        skip = (buf[2] << 0) | (buf[3] << 8);
#if CONFIG_SEND_HOSTADP_MODE
        if (skip + WIFI_80211_RAW_HDR_LEN >= ret || buf[skip] != 0x08) continue;
        if (memcmp(buf + skip + 4, s_mac_ff, sizeof(s_mac_ff)) != 0) continue; // if not broadcast
#else
        if (skip + WIFI_80211_RAW_HDR_LEN >= ret || buf[skip] != 0x88) continue;
        if (memcmp(buf + skip + 10 + 6, s_mac_ff, sizeof(s_mac_ff)) != 0) continue; // if not broadcast
#endif
        if (memcmp(rx->sniffe_mac, s_mac_00, sizeof(rx->sniffe_mac)) != 0 && memcmp(rx->sniffe_mac, buf + skip + 10 + 0, sizeof(rx->sniffe_mac)) != 0) continue;

        printf("%03X ", ret - skip - WIFI_80211_RAW_HDR_LEN);
        for (i=skip; i<ret&&i<76; i++) {
            printf("%02X ", buf[i]);
        }
        printf("\n"); fflush(stdout);

        len = ret - skip - WIFI_80211_RAW_HDR_LEN;
        idx =(len >> 4);
        if (idx < 0) continue;

        item = get_item_by_mac(rx->macdatlist, MAX_MACDATITEM_NUM, buf + skip + 10);
        rxdat= rx->macdatlist[item].dat;
        rx->macdatlist[item].counter++;

//      printf("+item: %d, counter: %d, diff: %d\n", item, rx->macdatlist[item].counter, (int32_t)get_tick_count() - (int32_t)rx->sniffe_tick0); fflush(stdout);
        if (rx->macdatlist[item].counter > 2) rx->sniffe_tick0 = get_tick_count() + rx->sniffe_tmin;
//      printf("-item: %d, counter: %d, diff: %d\n", item, rx->macdatlist[item].counter, (int32_t)get_tick_count() - (int32_t)rx->sniffe_tick0); fflush(stdout);

        mask   =(idx & 0x1) ? 0xF0 : 0x0F;
        code   =(idx & 0x1) ? ((len & 0xF) << 4) : ((len & 0xF) << 0);
        change = 0;
        if (code != (rxdat[idx / 2] & mask)) {
            rxdat[idx / 2] &= ~mask;
            rxdat[idx / 2] |=  code;
            change = 1;
        }
        if (change && rxdat[0] > 0 && rxdat[0] <= MAX_DATA_UNIT_SIZE) {
            calculate_checksum(rxdat, 1 + rxdat[0], &checksum0, &checksum1);
            if (rxdat[rxdat[0] + 1] == checksum0 && rxdat[rxdat[0] + 2] == checksum1) {
                if (rx->callback && rx->callback(rx->sniffe_chnl, rx->macdatlist[item].mac, rxdat + 1, rxdat[0]) == 1) {
                    memset(rx->macdatlist, 0, sizeof(rx->macdatlist));
                    snprintf(cmd, sizeof(cmd), "iwconfig %s mode managed", rx->netdev); system(cmd);
                    rx->callback = NULL;
                }
            }
        }
    }

    if (rawfd > 0) close(rawfd);
#endif
    return NULL;
}

void* smartlinkrx_init(char *dev)
{
    SMARTLINKRX *rx = calloc(1, sizeof(SMARTLINKRX));
    if (!rx) return NULL;
    strncpy(rx->netdev, dev, sizeof(rx->netdev));
    pthread_create(&rx->pthread, NULL, smartlinkrx_thread_proc, rx);
    return rx;
}

void smartlinkrx_exit(void *ctx)
{
    SMARTLINKRX *rx = (SMARTLINKRX*)ctx;
    if (!ctx) return;
    rx->flags |= RXFLAG_EXIT;
    pthread_join(rx->pthread, NULL);
    free(rx);
}

void smartlinkrx_recv(void *ctx, int channel, uint8_t *mac, int sniffetmin, int sniffetmax, PFN_SMARTLINK_CALLBCK callback)
{
    char cmd[256];
    SMARTLINKRX *rx = (SMARTLINKRX*)ctx;
    if (!ctx) return;
    memset(rx->macdatlist, 0, sizeof(rx->macdatlist));
    if (channel / 100) rx->flags |= RXFLAG_SCAN_CHANNEL;
    else               rx->flags &=~RXFLAG_SCAN_CHANNEL;
    channel        %= 100;
    rx->callback    = callback;
    rx->sniffe_chnl = channel < 1 ? 1 : channel > 13 ? 13 : channel;
    rx->sniffe_tmin = sniffetmin ? sniffetmin : 100 ;
    rx->sniffe_tmax = sniffetmax ? sniffetmax : 1000;
    rx->sniffe_tick0= get_tick_count() + rx->sniffe_tmin;
    rx->sniffe_tick1= get_tick_count() + rx->sniffe_tmax;
    if (mac) memcpy(rx->sniffe_mac, mac, sizeof(rx->sniffe_mac));
    else     memset(rx->sniffe_mac, 0  , sizeof(rx->sniffe_mac));
    snprintf(cmd, sizeof(cmd), "iwconfig %s mode %s && iwconfig %s channel %d", rx->netdev, callback ? "monitor" : "managed", rx->netdev, rx->sniffe_chnl);
    system(cmd);
}

#ifdef _TEST_
static int rx_recv_callbck(int channel, uint8_t *mac, uint8_t *buf, int len)
{
    printf("channel: %d, mac: %02X%02X%02X%02X%02X%02X, data: %2d %s\n", channel, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], len, buf); fflush(stdout);
    return 1;
}

static void strmac2hexmac(uint8_t hexmac[6], char *strmac)
{
    int i = 0;
    while (*strmac && i < 32) {
        int val = 0;
        if      (*strmac >= '0' && *strmac <= '9') val = *strmac - '0';
        else if (*strmac >= 'a' && *strmac <= 'f') val = *strmac - 'a' + 10;
        else if (*strmac >= 'A' && *strmac <= 'F') val = *strmac - 'A' + 10;
        hexmac[i / 2] &= (i & 1) ? 0xF0 : 0x0F;
        hexmac[i / 2] |= (i & 1) ? (val << 0) : (val << 4);
        strmac++; i++;
    }
    printf("hexmac: %02X%02X%02X%02X%02X%02X\n", hexmac[0], hexmac[1], hexmac[2], hexmac[3], hexmac[4], hexmac[5]); fflush(stdout);
}

int main(void)
{
    void *tx = NULL, *rx = NULL;
    while (1) {
        char cmd[256], buf[256];
        scanf("%256s", cmd);
        if (strcmp(cmd, "send_start") == 0) {
            int interval = 0;
            scanf("%256s %d", buf, &interval);
            if (!tx) tx = smartlinktx_init("wlan0");
            smartlinktx_send(tx, (uint8_t*)buf, strlen(buf) + 1, interval);
        } else if (strcmp(cmd, "send_stop") == 0) {
            smartlinktx_send(tx, NULL, 0, 0);
        } else if (strcmp(cmd, "recv_start") == 0) {
            int channel = 0, tmin = 0, tmax = 0; char strmac[256] = ""; uint8_t hexmac[6] = {};
            scanf("%d %s %d %d", &channel, strmac, &tmin, &tmax);
            strmac2hexmac(hexmac, strmac);
            if (!rx) rx = smartlinkrx_init("wlan0");
            smartlinkrx_recv(rx, channel, hexmac, tmin, tmax, rx_recv_callbck);
        } else if (strcmp(cmd, "recv_stop") == 0) {
            smartlinkrx_recv(rx, 0, NULL, 0, 0, NULL);
        } else if (strcmp(cmd, "help") == 0) {
            printf("smartlink v1.0.0.0\n");
            printf("available commmand:\n");
            printf("- help: show this mesage.\n");
            printf("- quit: quit this program.\n");
            printf("- send_start str interval: start send data.\n");
            printf("  - str is the data to send\n");
            printf("  - interval controls the send speed by ms\n");
            printf("    you can use 0 for default.\n");
            printf("- send_stop: stop send data.\n");
            printf("- recv_start channel mac locktime_min locktime_max: start recv data.\n");
            printf("  - channel range: [0, 13], if using 1xx it will auto scan\n");
            printf("  - mac: which mac we want to sniffe, if using null will sniffe all mac\n");
            printf("  - locktime_min: the timeout checking for getting data on channel.\n");
            printf("    you can use 0 for default.\n");
            printf("  - locktime_max: the timeout checking after getting data on channel.\n");
            printf("    you can use 0 for default.\n");
            printf("- recv_stop: stop recv data.\n");
            fflush(stdout);
        } else if (strcmp(cmd, "quit") == 0 || strcmp(cmd, "exit") == 0) {
            break;
        }
    }
    smartlinktx_exit(tx);
    smartlinkrx_exit(rx);
    return 0;
}
#endif
