#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "helper.h"

void tcp(char*);
void tcp6(char*);
void udp(char*);
void udp6(char*);
int main(int argv, char *args[]) {
    tcp("");
    tcp6("");
    udp("");
    udp6("");
    return 0;
}
void tcp(char* filter) {
    printf("List of TCP connections:\nProto Local Address\tForeign Address\tPID/Program name and arguments\n");
    //tcp ipv4
    FILE *fp;
    char* buffer  = malloc(255*sizeof(char));
    fp = fopen("/proc/net/tcp", "r");
    fgets(buffer, 255, fp);
    while(!feof(fp)) {
        char* line = malloc(255*sizeof(char));
        fgets(buffer, 255, fp);
        //parse a line
        char* local_addr = malloc(20*sizeof(char));
        char* local_port = malloc(8*sizeof(char));
        char* remote_addr = malloc(20*sizeof(char));
        char* remote_port = malloc(8*sizeof(char));
        char* inode = malloc(12*sizeof(char));
        //get the essential parameters
        sscanf(buffer, "%*s %[^:]%*c%s %[^:]%*c%s %*s %*s %*s %*s %*s %*s %s", local_addr, local_port,  remote_addr, remote_port, inode); 

        sprintf(line, "tcp %s:%s\t%s:%s\t%s",hex_to_ipv4(local_addr), hex_to_num(local_port), hex_to_ipv4(remote_addr),hex_to_num(remote_port)  , inode_to_proc(inode));
        printf("%s\n", line);
        free(local_addr);
        free(local_port);
        free(remote_addr);
        free(remote_port);
        free(inode);
        free(line);
    }
    free(buffer);
    fclose(fp);
}
void tcp6(char* filter) {
    //tcp ipv6
    FILE *fp;
    char* buffer  = malloc(255*sizeof(char));
    fp = fopen("/proc/net/tcp6", "r");
    fgets(buffer, 255, fp);
    while(!feof(fp)) {
        char* line = malloc(255*sizeof(char));
        fgets(buffer, 255, fp);
        //parse a line
        char* local_addr = malloc(40*sizeof(char));
        char* local_port = malloc(8*sizeof(char));
        char* remote_addr = malloc(40*sizeof(char));
        char* remote_port = malloc(8*sizeof(char));
        char* inode = malloc(12*sizeof(char));
        //get the essential parameters
        sscanf(buffer, "%*s %[^:]%*c%s %[^:]%*c%s %*s %*s %*s %*s %*s %*s %s", local_addr, local_port,  remote_addr, remote_port, inode); 
        //printf("%s \n", inode_to_proc(inode));
        sprintf(line,"tcp6 %s:",hex_to_ipv6(local_addr));
        sprintf(line, "%s%s\t",line, hex_to_num(local_port));
        sprintf(line,"%s%s:",line, hex_to_ipv6(remote_addr));
        sprintf(line, "%s%s\t",line, hex_to_num(remote_port));
        sprintf(line, "%s%s ",line, inode_to_proc(inode));
        //printf("tcp6 %s:%s\t%s:%s\t%s\n",hex_to_ipv6(local_addr), hex_to_num(local_port), hex_to_ipv6(remote_addr),hex_to_num(remote_port)  , inode_to_proc(inode));
        printf("%s\n", line);
        free(local_addr);
        free(local_port);
        free(remote_addr);
        free(remote_port);
        free(inode);
        free(line);
    }
    free(buffer);
    fclose(fp);
}
void udp(char* filter) {
    printf("List of UDP connections:\nProto Local Address\tForeign Address\tPID/Program name and arguments\n");
    //udp ipv4
    FILE *fp;
    char* buffer  = malloc(255*sizeof(char));
    fp = fopen("/proc/net/udp", "r");
    fgets(buffer, 255, fp);
    while(!feof(fp)) {
        char* line = malloc(255*sizeof(char));
        fgets(buffer, 255, fp);
        //parse a line
        char* local_addr = malloc(20*sizeof(char));
        char* local_port = malloc(8*sizeof(char));
        char* remote_addr = malloc(20*sizeof(char));
        char* remote_port = malloc(8*sizeof(char));
        char* inode = malloc(12*sizeof(char));
        //get the essential parameters
        sscanf(buffer, "%*s %[^:]%*c%s %[^:]%*c%s %*s %*s %*s %*s %*s %*s %s", local_addr, local_port,  remote_addr, remote_port, inode); 

        sprintf(line,"udp %s:",hex_to_ipv4(local_addr));
        sprintf(line, "%s%s\t",line, hex_to_num(local_port));
        sprintf(line,"%s%s:",line, hex_to_ipv4(remote_addr));
        sprintf(line, "%s%s\t",line, hex_to_num(remote_port));
        sprintf(line, "%s%s ",line, inode_to_proc(inode));
        printf("%s\n", line);
        free(local_addr);
        free(local_port);
        free(remote_addr);
        free(remote_port);
        free(inode);
        free(line);
    }
    free(buffer);
    fclose(fp);
}
void udp6(char* filter) {
    //tcp ipv6
    FILE *fp;
    char* buffer  = malloc(255*sizeof(char));
    fp = fopen("/proc/net/udp6", "r");
    fgets(buffer, 255, fp);
    while(!feof(fp)) {
        char* line = malloc(255*sizeof(char));
        fgets(buffer, 255, fp);
        //parse a line
        char* local_addr = malloc(40*sizeof(char));
        char* local_port = malloc(8*sizeof(char));
        char* remote_addr = malloc(40*sizeof(char));
        char* remote_port = malloc(8*sizeof(char));
        char* inode = malloc(12*sizeof(char));
        //get the essential parameters
        sscanf(buffer, "%*s %[^:]%*c%s %[^:]%*c%s %*s %*s %*s %*s %*s %*s %s", local_addr, local_port,  remote_addr, remote_port, inode); 
        //printf("%s \n", inode_to_proc(inode));
        sprintf(line,"udp6 %s:",hex_to_ipv6(local_addr));
        sprintf(line, "%s%s\t",line, hex_to_num(local_port));
        sprintf(line,"%s%s:",line, hex_to_ipv6(remote_addr));
        sprintf(line, "%s%s\t",line, hex_to_num(remote_port));
        sprintf(line, "%s%s ",line, inode_to_proc(inode));
        
        printf("%s\n", line);
        free(local_addr);
        free(local_port);
        free(remote_addr);
        free(remote_port);
        free(inode);
        free(line);
    }
    free(buffer);
    fclose(fp);
}
