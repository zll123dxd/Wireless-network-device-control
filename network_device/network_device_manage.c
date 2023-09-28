#include "network_device_manage.h"
//#include <net/nl80211.h>
#define be_to_int_ipaddr(addr)\
  ((unsigned char*)&addr)[0],\
  ((unsigned char*)&addr)[1],\
  ((unsigned char*)&addr)[2],\
  ((unsigned char*)&addr)[3]

#define be_to_int_mask(mask)\
  ((unsigned char*)&mask)[0]

int init_sock() {
    int sock = 0;
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    return sock;
}

int set_interface_state(char *iface_name, int state) {
    int result = 0;
    int sock;
    struct ifreq irq;
    sock = init_sock();
    if (!sock) {
        printf("socket create error\n");
    }
    memset(&irq, '\0', sizeof(struct ifreq));
    strcpy(irq.ifr_name, iface_name);
    result = ioctl(sock, SIOCGIFFLAGS, (caddr_t)&irq);    
    if (result) {
        printf("set_interface_state : SIOCGIFFLAGS error\n");
        goto error;
    }

    if (state) {
        irq.ifr_flags |= IFF_UP;
    } else {
        irq.ifr_flags &= ~IFF_UP;
    }

    result = ioctl(sock, SIOCSIFFLAGS, (caddr_t)&irq);
    if (result) {
        printf("set_interface_state : SIOCSIFFLAGS error : %d , please try to use root\n", result);
        goto error;
    }

error:
    close(sock);
    return result;
}

int check_iface_state(char *iface_name) {
    int result = 0;
    int sock;
    struct ifreq irq;
    sock = init_sock();
    memset(&irq, '\0', sizeof(struct ifreq));
    strcpy(irq.ifr_name, iface_name);
    result = ioctl(sock, SIOCGIFFLAGS, (caddr_t)&irq);
    if (result) {
        printf("check_iface_state : SIOCGIFFLAGS error\n");
        result = -1;
        goto error;
    }

    if (irq.ifr_flags & IFF_UP) {
        result = 1;
    } else {
        result = 0;
    }

error:
    close(sock);
    return result;
}

int get_net_dev_mac(char *iface_name, unsigned char* mac) {
    int result = 0;
    int sock;
    struct ifreq irq;
    sock = init_sock();
    memset(&irq, '\0', sizeof(struct ifreq));
    strcpy(irq.ifr_name, iface_name);
    result = ioctl(sock, SIOCGIFHWADDR, &irq);
    if (result) {
        printf("get_net_dev_mac : SIOCGIFHWADDR error\n");
        result = -1;
        goto error;
    }

    if (irq.ifr_hwaddr.sa_family == ARPHRD_ETHER) {
        memcpy(mac, irq.ifr_hwaddr.sa_data, 6);
    } else {
        result = -1;
    }
error :
    close(sock);
    return result;
}

int net_eth_get_ipv4_addr(char *iface_name, unsigned char *ip_addr, unsigned char *netmask) {
    int result = 0;
    int sock;
    struct ifreq irq;
    sock = init_sock();
    memset(&irq, '\0', sizeof(struct ifreq));
    strcpy(irq.ifr_name, iface_name);
    result = ioctl(sock, SIOCGIFADDR, &irq);

    if (result < 0) {
        printf("net_eth_get_ipv4_addr : SIOCGIFADDR error\n");
        result = -1;
        goto error;
    }

    if (irq.ifr_addr.sa_family != AF_INET) {
        printf("net_eth_get_ipv4_addr: SIOCGIFADDR : ifreq is not inet. error\n");
        result = -1;
        goto error;
    }

    struct sockaddr_in *addr = (struct sockaddr_in*)&(irq.ifr_addr);
    memcpy(ip_addr, &(addr->sin_addr.s_addr), 4);

    result = ioctl(sock, SIOCGIFNETMASK, &irq);
    if (result < 0) {
        printf("net_eth_get_ipv4_addr : SIOCGIFNETMASK error\n");
        result = -1;
        goto error;
    }

    if (irq.ifr_netmask.sa_family != AF_INET) {
        printf("net_eth_get_ipv4_addr: SIOCGIFNETMASK : ifreq is not inet. error\n");
        result = -1;
        goto error;
    }

    addr = (struct sockaddr_in *)&(irq.ifr_netmask);
    memcpy(netmask, &(addr->sin_addr.s_addr), 4);
error :
    close(sock);
    return result;
}

int net_dev_set_macaddr(char *iface_name, unsigned char *mac) {
    int result = 0;
    int sock;
    struct ifreq irq;
    short flag;
    sock = init_sock();
    memset(&irq, '\0', sizeof(struct ifreq));
    strcpy(irq.ifr_name, iface_name);
    result = ioctl(sock, SIOCGIFFLAGS, &irq);
    if (result) {
        printf("net_dev_set_macaddr : SIOCGIFFLAGS error\n");
        result = -1;
        goto error;
    }

    flag = irq.ifr_flags;
    if (flag & IFF_UP) {
        irq.ifr_flags &= ~IFF_UP;
        ioctl(sock, SIOCSIFFLAGS, &irq);
    }

    irq.ifr_hwaddr.sa_family = ARPHRD_ETHER;
    memcpy(irq.ifr_hwaddr.sa_data, mac, 6);
    result = ioctl(sock, SIOCSIFHWADDR, &irq);

    if (result) {
        printf("net_dev_set_macaddr : SIOCSIFHWADDR error\n");
        result = -1;
        goto error;
    }

    if (flag & IFF_UP) {
        ioctl(sock, SIOCGIFFLAGS, &irq);
        irq.ifr_flags |= IFF_UP;
        ioctl(sock, SIOCSIFFLAGS, &irq);
    }
error:
    close(sock);
    return result;
}

int net_dev_set_ipaddr(char *iface_name, unsigned char *ipaddr, unsigned char*netmask) {
    int result = 0;
    int sock;
    struct ifreq irq;
    sock = init_sock();
    memset(&irq, '\0', sizeof(struct ifreq));
    strcpy(irq.ifr_name, iface_name);

    irq.ifr_addr.sa_family = AF_INET;
    struct sockaddr_in *addr = (struct sockaddr_in *)&(irq.ifr_addr);
    memcpy(&(addr->sin_addr.s_addr), ipaddr, 4);
    addr = (struct sockaddr_in *)&(irq.ifr_netmask);
    memcpy(&(addr->sin_addr.s_addr), netmask, 4);
    result = ioctl(sock, SIOCSIFADDR, &irq);
    if (result) {
        printf("net_dev_set_ipaddr : SIOCSIFADDR error\n");
        result = -1;
        goto error;
    }

error:
    close(sock);
    return result;
}


int StringToHex(char *str, unsigned char *out, unsigned int *outlen)
{
    char *p = str;
    char high = 0, low = 0;
    int tmplen = strlen(p), cnt = 0;
    tmplen = strlen(p);
    while(cnt < (tmplen / 2))
    {
        high = ((*p > '9') && ((*p <= 'F') || (*p <= 'f'))) ? *p - 48 - 7 : *p - 48;
        low = (*(++ p) > '9' && ((*p <= 'F') || (*p <= 'f'))) ? *(p) - 48 - 7 : *(p) - 48;
        out[cnt] = ((high & 0x0f) << 4 | (low & 0x0f));
        p ++;
        cnt ++;
    }
    if(tmplen % 2 != 0) out[cnt] = ((*p > '9') && ((*p <= 'F') || (*p <= 'f'))) ? *p - 48 - 7 : *p - 48;
    
    if(outlen != NULL) *outlen = tmplen / 2 + tmplen % 2;
    return tmplen / 2 + tmplen % 2;
}

typedef void (*_SEEK_PROCESS) (uint16_t freq);

int main(int argc, char *argv[])
{ 
    for (int i = 1 ; i < argc-1; i++) {
        char* iface = argv[i];
        int up = argv[i+1][0] - '0';

        char macArray[7];
        unsigned char* mac = macArray;
        char mac_result[64];
        unsigned char ip_addr[5];
        unsigned char mask[5];
        unsigned char mac_addr[6] = {0x12,0x34,0x56,0x78,0x90,0x11};

        if (up) {
            // up
            unsigned char net_ipaddr[4] = {192,168,112,57};
            unsigned char net_mask[4] = {192,168,112,57};
            printf("try to config network\n");
            printf("up interface\n");
            set_interface_state(iface, 1);
            printf("config ipAddr\n"); 
            net_dev_set_ipaddr(iface, net_ipaddr, net_mask);
        } else {
            // down
            if (check_iface_state(iface)) {
                get_net_dev_mac(iface, mac);
                snprintf(mac_result, 64, "%02X:%02X:%02X:%02X:%02X:%02X", *mac, *(mac+1), *(mac+2), *(mac+3) ,*(mac+4) ,*(mac+5));
                printf("iface : %s is up, mac addr = %s\n", iface, mac_result); 
                if (!net_eth_get_ipv4_addr(iface, ip_addr, mask)) {
                    printf("iface : %s is up, ip addr = %d.%d.%d.%d , mask = %d.%d.%d.%d\n", iface, be_to_int_ipaddr(ip_addr), be_to_int_ipaddr(mask)); 
                }
            }
            set_interface_state(iface, 0);
        }
    }
    return 0;
}

