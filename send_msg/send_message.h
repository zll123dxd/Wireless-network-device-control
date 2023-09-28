#include <stdio.h>
#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <arpa/inet.h>

#include <sys/ioctl.h>
#include <sys/time.h>

#include <net/if.h>
#include <netpacket/packet.h>

#include <linux/if_ether.h>
#include <pcap.h>

#define BEACON 0
#define DEAUTHENTICATION 1
#define DISASSOCIATE 2

typedef unsigned char bool;
typedef signed char int8;
typedef unsigned char uint8;
typedef signed short int16;
typedef unsigned short uint16;
typedef signed int int32;
typedef unsigned int uint32;
typedef signed long long int64;
typedef unsigned long long uint64;

struct frame_config {
    uint8 source_bssid[6];
    uint8 des_bssid[6];
    uint16 seq_id;
    uint8 essid_len;
    char essid[32];
    char country_code[2];
    char iface[32];
    uint8 interval;
    uint8 type;
};

struct disable_config {
    uint8 ssid_len;
    char ssid[32];
    uint8 ap_bssid[6];

    uint8 allow_bssid_num;
    uint8 bssids[20][6];
};
