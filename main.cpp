#if 1

#ifdef __cplusplus
#define _CRT_SECURE_NO_WARNINGS
#endif
#include <string.h>
#include <stdio.h>
//#include <pcap/pcap.h>
#include <pcap/pcap.h>
#include <pcap-int.h>

#define DEBUG 1


#define pathIndex 0
#define paramsListBegin 1
#define srcAddrIndex paramsListBegin
#define dstAddrIndex 2
#define srdPortIndex 3
#define paramsListEnd 4
#define dstPortIndex paramsListEnd

#define pathPrefix "--path="
#define srcAddrPrefix "--srcaddr="
#define dstAddrPrefix "--dstaddr="
#define srcPortPrefix "--srcport="
#define dstPortPrefix "--dstport="


extern int pcap_findalldevs(pcap_if_t**, char*);

typedef struct params{
    const char* name;
    const char *value; 
} params_t;



int main(const int argc, const char** argv)
{
    params_t paramsList[] = 
    {   
        pathPrefix,
        srcAddrPrefix,
        dstAddrPrefix,
        srcPortPrefix,
        dstPortPrefix,
    };

#if DEBUG
    if(argc < 2){
        paramsList[0].value = "./sniffList.pcap";
        paramsList[1].value = "127.0.0.1";
        paramsList[2].value = "127.0.0.1";
        paramsList[3].value = "42";
        paramsList[4].value = "24";
    }
#else
    if(argv[1] == NULL)
        return -1;
    paramsList[pathIndex].value = strstr(argv[1], paramsList[pathIndex].name);
    if(paramsList[pathIndex].value == NULL) return -1;

    for(int argIt = 2; argIt < argc; ++argIt){
        for (int paramsIt = paramsListBegin; paramsIt < paramsListEnd; ++paramsIt) {
            if(paramsList[paramsIt].value != NULL) break;
            paramsList[paramsIt].value = strstr(argv[argIt], paramsList[paramsIt].name);
            if(paramsList[paramsIt].value == NULL) continue;
        }close
    }
#endif
    char *dev=NULL, *errbuf = NULL;
    int devCounter;
    pcap_if_t *devicelist;
    pcap_t *m_hCardSource, *pcapFile_s;

#if 0
    //получаем список всех сетевых устройств(адаптеров)
    devCounter = pcap_findalldevs(&devicelist, errbuf);
        
    //открываем устройство
    //m_hCardSource = pcap_open_live(device->name, 65536, 1, -1, errbuf);

    if ( devicelist->name == NULL) 
    {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }else{
        printf("Available devices: %s\n");
        while (devicelist)
        {
            printf("-%s\n", devicelist->name);
            devicelist = devicelist->next;
        }
    }
#endif

    pcapFile_s = pcap_open_offline(paramsList[pathIndex].value, errbuf);    
}
#endif