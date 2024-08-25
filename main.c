#include <string.h>
#include <stdio.h>
#include <pcap/pcap.h>
#include <stdlib.h>

#define __DEBUG false

#define pathIndex 0
#define paramsListBegin 1
#define srcAddrIndex paramsListBegin
#define dstAddrIndex 2
#define srdPortIndex 3
#define paramsListEnd 4
#define dstPortIndex paramsListEnd

#define pathPrefix "--path"
#define srcAddrPrefix "--srcaddr"
#define dstAddrPrefix "--dstaddr"
#define srcPortPrefix "--srcport"
#define dstPortPrefix "--dstport"

#define OK_rc 1

extern int pcap_findalldevs(pcap_if_t**, char*);

typedef struct params{
    const char* name;
    char *descr;
    char *value; 
} params_t;

pcap_handler ph_callback(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet){  
    #if __DEBUG
        printf("packet length=%d/%d\n",header->caplen, header->len);
        printf("raw Packet: %s\n", packet);
    #endif
};

int main(const int argc, const char** argv)
{
    char *errbuf;
    pcap_t *pcapFile_h[3];
    struct bpf_program filter;
    char filter_str[] = "ip proto \\tcp";

    params_t paramsList[5] = 
    {   
        {pathPrefix,NULL, NULL},
        {srcAddrPrefix,"src host", NULL},
        {dstAddrPrefix,"dst host", NULL},
        {srcPortPrefix,"src port", NULL},
        {dstPortPrefix,"dst port", NULL}
    };

    char *path_str;
#if __DEBUG
    if(argc < 2){
        paramsList[0].value = "./sniffList.pcap";
        paramsList[srcAddrIndex].value = "127.0.0.1";
        paramsList[dstAddrIndex].value = "127.0.0.1";
        paramsList[srcPortPrefix].value = "42";
        paramsList[dstPortPrefix].value = "24";
    }
    path_str = paramsList[0].value;
#else

    printf("Try to open .pcap file\n");
    if(argv[1] == NULL || argv[1] == strlen(pathPrefix)){
        printf("Path to .pcap file is not exist\n");   
        return -1;
    }
    path_str = strstr(argv[1], "=")+1;

    for(int argIt = 2; argIt < argc; ++argIt){
        for (int paramsIt = paramsListBegin; paramsIt < paramsListEnd+1; ++paramsIt) {
            //если в переменной уже что-то есть то пропускаем её
            if(paramsList[paramsIt].value != NULL) continue;

            if(strstr(argv[argIt], paramsList[paramsIt].name) != 0){
                char* value = strstr(argv[argIt], "=");
                paramsList[paramsIt].value = strstr(argv[argIt], "=")+1;
                break;
            }else{
                continue;
            }
        }
    }
#endif

    FILE *path;
    for(int it = 0; it < 3; ++it){
        path = fopen(path_str, "r");
        if (path == NULL) {
            printf("file %s is not exist\n", path_str);
            return 0;
        }
        pcapFile_h[it] = pcap_open_offline(path_str, errbuf); 
        paramsList[pathIndex].value = path_str;
    }
    printf(".pcap successfully opened\n");

    for(int it = 0; it < paramsListEnd+1; ++it){
        char *value = (paramsList[it].value == ' ') ? "empty" : paramsList[it].value;
        printf("%s=%s\n", paramsList[it].name, value);
    }

  
    int totalPackets = pcap_dispatch(pcapFile_h[0], -1, ph_callback, NULL);

    ///TOTAL TCP CALCULATE
    if (pcap_compile(pcapFile_h[1], &filter, filter_str, 1, PCAP_NETMASK_UNKNOWN) != 0) {
        pcap_close(pcapFile_h[1]);
        printf("Couldn`t compile TCP filter %s\n", errbuf);
    }
    if(pcap_setfilter(pcapFile_h[1], &filter)){
        printf("Couldn't set TCP filter\n");
        return 0;
    } 
    int totalTCPpackets = pcap_dispatch(pcapFile_h[1], -1, ph_callback, NULL);

    ///FILTERED PACKETS CALCULATE
#if 1
    for(int pos = paramsListBegin; pos < paramsListEnd+1; ++pos){
        if(paramsList[pos].value != NULL){
            strncat(filter_str, " and ", 5);
            strncat(filter_str, paramsList[pos].descr , strlen(paramsList[pos].descr));
            strncat(filter_str, " ", 1);
            strncat(filter_str, paramsList[pos].value , strlen(paramsList[pos].value));
        }
    }
#endif

    printf("Try to find packets with filter: %s\n", filter_str);                                    
    if (pcap_compile(pcapFile_h[2], &filter, filter_str, 1, PCAP_NETMASK_UNKNOWN) != 0) {
        pcap_close(pcapFile_h[2]);                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            
        printf("Couldn`t compile filter %s\n", errbuf);
    }
    if(pcap_setfilter(pcapFile_h[2], &filter)){
        printf("Couldn't set filter\n");
        return 0;
    } 
    int FilteredTCPpackets = pcap_dispatch(pcapFile_h[2], -1, ph_callback, NULL);
    
    printf("Total packets counter: %d\nTotal TCP packets counter: %d\nTotal filtered packets counter: %d\n",  totalPackets, totalTCPpackets, FilteredTCPpackets);
    printf("exiting from programm...\n");
    close(path);
    pcap_freecode(&filter);
}