#include <string.h>
#include <stdio.h>
#include <pcap/pcap.h>
#include <stdlib.h>

#define __DEBUG 0

#define pathIndex 0
#define paramsListBegin 1
#define srcAddrIndex paramsListBegin
#define dstAddrIndex 2
#define srcPortIndex 3
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

typedef enum bool{
    false = 0,
    true = 1
}bool;


void ph_callback(unsigned char  *args, const struct pcap_pkthdr *header, const unsigned char *packet){  
#if __DEBUG
    printf("packet length=%d/%d\nraw Packet: ",header->caplen, header->len);
    const char* curPos = packet;
    int counter = 0;
    while(*curPos != 0){
        printf("%02hhx ", *curPos);
        counter++;
        curPos = curPos+1;
    }
    printf("\n");
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
        {pathPrefix, NULL, NULL},
        {srcAddrPrefix,"src host ", NULL},
        {dstAddrPrefix,"dst host ", NULL},
        {srcPortPrefix,"src port ", NULL},
        {dstPortPrefix,"dst port ", NULL}
    };

    char *path_str;
#if __DEBUG
    if(argc < 2){
        paramsList[pathIndex].value = "./sniffList.pcap";
        paramsList[srcAddrIndex].value = "127.0.0.1";
        paramsList[dstAddrIndex].value = "127.0.0.1";
        paramsList[srcPortIndex].value = "42";
        paramsList[dstPortIndex].value = "24";
    }
    path_str = strstr(argv[1], "=")+1;

    printf("Try to open .pcap file...\n");
#else

    bool pathArgValid = true;
    if(argv[1] == NULL){
          pathArgValid = false;
    }else{
        path_str = strstr(argv[1], "=");
        if(path_str != NULL){
            if(strlen(pathPrefix)+strlen(path_str) != strlen(argv[1])){
                pathArgValid = false;
            }
        }else{
          pathArgValid = false;
        }
    }

    if(pathArgValid == false){
        printf("Path to .pcap file is invalid\n");   
        return -1;
    }
    path_str = &*(path_str+1);

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
            printf("file with path %s is not exist\n", path_str);
            return 0;
        }
        pcapFile_h[it] = pcap_open_offline(path_str, errbuf); 
        paramsList[pathIndex].value = path_str;
    }
    printf(".pcap successfully opened\n");

#if __DEBUG
    for(int it = 0; it < paramsListEnd+1; ++it) 
        printf("%s=%s\n", paramsList[it].name, (paramsList[it].value == NULL) ? "empty" : paramsList[it].value );
#endif
  
    int totalPackets = pcap_dispatch(pcapFile_h[0], -1, ph_callback, NULL);

    ///TOTAL TCP CALCULATE
    if (pcap_compile(pcapFile_h[1], &filter, filter_str, 1, PCAP_NETMASK_UNKNOWN) != 0) {
        pcap_close(pcapFile_h[1]);
        printf("Couldn`t compile TCP filter %s\n", errbuf);
        return -1;
    }
    if(pcap_setfilter(pcapFile_h[1], &filter)){
        printf("Couldn't set TCP filter\n");
        return -1;
    } 
    int totalTCPpackets = pcap_dispatch(pcapFile_h[1], -1, ph_callback, NULL);

    ///FILTERED PACKETS CALCULATE
    char* filterDelimiter = " and ";
    for(int pos = paramsListBegin; pos < paramsListEnd+1; ++pos){
        if(paramsList[pos].value != NULL){
            strncat(filter_str, filterDelimiter, strlen(filterDelimiter));
            strncat(filter_str, paramsList[pos].descr , strlen(paramsList[pos].descr));
            strncat(filter_str, paramsList[pos].value , strlen(paramsList[pos].value));
        }
    }

    printf("Try to find packets with filter: %s\n", filter_str);                                    
    if (pcap_compile(pcapFile_h[2], &filter, filter_str, 1, PCAP_NETMASK_UNKNOWN) != 0) {
        pcap_close(pcapFile_h[2]);                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            
        printf("Couldn`t compile filter %s\n", errbuf);
        return -1;
    }
    if(pcap_setfilter(pcapFile_h[2], &filter)){
        printf("Couldn't set filter\n");
        return -1;
    } 
    int FilteredTCPpackets = pcap_dispatch(pcapFile_h[2], -1, ph_callback, NULL);
    
    printf("Total packets counter: %d\nTotal TCP packets counter: %d\nTotal filtered packets counter: %d\n",  totalPackets, totalTCPpackets, FilteredTCPpackets);
    printf("exiting from programm...\n");
    pclose(path);
    pcap_freecode(&filter);
}