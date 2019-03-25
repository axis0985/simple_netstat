#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <ctype.h>
#include <string.h>
#include "helper.h"

void proto(char*,char*);
void proto6(char*, char*);
int main(int argc, char *argv[]) {
    struct option long_options[] = {
        {"tcp", no_argument, NULL, 't'},
        {"udp", no_argument, NULL, 'u'},
        {0,0,0,0}
    };
    short tcp_flag = 0;
    short udp_flag = 0;
    char filter[64] = "";
    char opt;
    while((opt = getopt_long(argc, argv, "tu", long_options, NULL) ) != -1) {
        switch(opt) {
            case 't':
                tcp_flag = 1;
                break;
            case 'u':
                udp_flag = 1;
                break;
        }
    }
    for (int i = optind; i < argc; i++) {
        strcpy(filter, argv[i]);
    }
    if (tcp_flag) {
        proto("tcp",filter);
        proto6("tcp",filter);
    } else if (udp_flag) {
        proto("udp",filter);
        proto6("udp",filter);
    } else {
        proto("tcp",filter);
        proto6("tcp",filter);
        proto("udp",filter);
        proto6("udp",filter);
    }
    return 0;
}
void proto(char* protocol, char* filter) {
    char upper_p[12];
    strcpy(upper_p, protocol);
    for (int i = 0 ; i < strlen(upper_p); i++) 
        upper_p[i] = toupper(upper_p[i]);
    printf("List of %s connections:\nProto Local Address\tForeign Address\tPID/Program name and arguments\n",  upper_p);
    FILE *fp;
    char filename[64];
    char buffer[255];
    sprintf(filename, "/proc/net/%s", protocol);
    fp = fopen(filename, "r");
    fgets(buffer, 255, fp);
    char local_addr[20];
    char local_port[8];
    char remote_addr[20];
    char remote_port[8];
    char inode[12];
    while(fscanf(fp, "%*s %[^:]%*c%s %[^:]%*c%s %*s %*s %*s %*s %*s %*s %s %*[^\n]", local_addr, local_port,  remote_addr, remote_port, inode) == 5 ) {
        char line[255];
        char* l_ip= hex_to_ipv4(local_addr);
        char* l_port = hex_to_dec(local_port);
        char* r_ip= hex_to_ipv4(remote_addr);
        char* r_port = hex_to_dec(remote_port);
        char* proc = inode_to_proc(inode);
        if (strcmp(filter,"") ==0 || strstr(proc, filter) != NULL) {
            sprintf(line, "%s %s:%s\t%s:%s\t%s",protocol, l_ip, l_port, r_ip,r_port  , proc);
            printf("%s\n", line);
        }
        free(l_ip);
        free(l_port);
        free(r_ip);
        free(r_port);
        free(proc);
    }
    fclose(fp);
}
void proto6(char* protocol, char* filter) {
    FILE *fp;
    char filename[64];
    char buffer[255];
    sprintf(filename, "/proc/net/%s6", protocol);
    fp = fopen(filename, "r");
    fgets(buffer, 255, fp);
    char local_addr[40];
    char local_port[8];
    char remote_addr[40];
    char remote_port[8];
    char inode[12];
    while(fscanf(fp, "%*s %[^:]%*c%s %[^:]%*c%s %*s %*s %*s %*s %*s %*s %s %*[^\n]", local_addr, local_port,  remote_addr, remote_port, inode) == 5 ) {
        char line[255];
        char* l_ip= hex_to_ipv6(local_addr);
        char* l_port = hex_to_dec(local_port);
        char* r_ip= hex_to_ipv6(remote_addr);
        char* r_port = hex_to_dec(remote_port);
        char* proc = inode_to_proc(inode);
        if (strcmp(filter,"") ==0 || strstr(proc, filter) != NULL) {
            sprintf(line, "%s %s:%s\t%s:%s\t%s",protocol, l_ip, l_port, r_ip,r_port  , proc);
            printf("%s\n", line);
        }
        free(l_ip);
        free(l_port);
        free(r_ip);
        free(r_port);
        free(proc);
    }
    fclose(fp);
    printf("\n");
}