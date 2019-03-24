#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <dirent.h>

char* reverse_hex (char* hex) {
    char* res = malloc(40*sizeof(char));
	memset(res, 0 , 40*sizeof(char));
    int len = strlen(hex);
    // -2 to go from behind
    for(int i = len-2; i>=0 ; i-=2) {
        strncat(res, hex+i,2);
    }
    return res;
}
char* hex_to_dec(char* hex) {
    char* res = malloc(16*sizeof(char));
	memset(res, 0 , 16*sizeof(char));
    long int i = strtol(hex, NULL, 16);
    sprintf(res, "%ld", i );
    return res;
}
char* hex_to_num(char* hex) {
    char* rev_str = reverse_hex(hex);
    char* res = hex_to_dec(rev_str);
    free(rev_str);
    return res;
}
char* hex_to_ipv4(char* hex) {
    char* rev_str = reverse_hex(hex);
    char* res = malloc(40*sizeof(char));
    char* tmp_hex = malloc(4*sizeof(char));
	memset(res,0, sizeof(40*sizeof(char)));
    strncpy(tmp_hex, rev_str, 2);
    char* tmp_num = hex_to_dec(tmp_hex); 
    strcat(res, tmp_num);
    free(tmp_num);
    for (int i = 2; i < strlen(rev_str) ; i+=2) {
        strcat(res, ".");
        strncpy(tmp_hex, rev_str+i, 2);
        tmp_num = hex_to_dec(tmp_hex);
        strcat(res, tmp_num);
        free(tmp_num);
    }
    free(rev_str);
    free(tmp_hex);
    return res;
}
char* hex_to_ipv6(char* hex) {
    char* rev_str = reverse_hex(hex);
    //check ipv4
    char* check_ipv4_str = malloc(32*sizeof(char));
	memset(check_ipv4_str, 0, 32*sizeof(char));
    strcpy(check_ipv4_str, rev_str+8);
    free(rev_str);
    if (strcmp(check_ipv4_str, "0000FFFF0000000000000000") == 0) {
        char* res = malloc(20*sizeof(char));
		memset(res,0, sizeof(20*sizeof(char)));
        char* ipv4 = hex_to_ipv4(hex+24);
        strcat(res, "::ffff:");
        strcat(res, ipv4);
        free(check_ipv4_str);
        free(ipv4);
        return res;
    }
	free(check_ipv4_str);
    // ipv6 endian conversion 
    // AAAA AAAA:BBBB BBBB:CCCC CCCC:DDDD DDD
    char* ipv6 = malloc(40*sizeof(char));
    char* tmp = malloc(12*sizeof(char));
	memset(ipv6,0, 40*sizeof(char));
	memset(tmp, 0, 12*sizeof(char));
    for ( int i = 0 ; i < 4 ; i++ ) {
        strncpy(tmp, hex+8*i,8);
        char* tmp_hex = reverse_hex(tmp);
        strcat(ipv6, tmp_hex);
        free(tmp_hex);
    }
    for (int i = 0 ; i < strlen(ipv6) ; i++) {
        *(ipv6+i) = tolower(*(ipv6+i));
    }
    short abbrev = 0; //1 if :: is used once 2 for the end
    char* res = malloc(40*sizeof(char));
    char* tmp_hex = malloc(8*sizeof(char));
	memset(res,0, 40*sizeof(char));
	memset(tmp_hex,0, 8*sizeof(char));
    for (int i = 0 ; i < 8 ; i++) {
        strncpy(tmp_hex, ipv6+i*4, 4);
        if (strcmp(tmp_hex, "0000") == 0) {
            if ( abbrev == 0) {
                abbrev = 1;
                strcat(res, ":");
                continue;
            } else if (abbrev == 1 && i == 7) {
                strcat(res, ":");
                continue;
            } else if (abbrev == 1) {
                continue;
            }
        }
        if (abbrev == 1) {
            abbrev = 2;
        }
        int offset = 0;
        for ( offset = 0 ; offset < 3; offset++) {
            if (*(tmp_hex+offset) != '0') {
                break;
            }
        }
        if (i!=0) strcat(res, ":");
        strcat(res, tmp_hex+offset);
    }
	free(tmp_hex);
	free(ipv6);
	free(tmp);
    return res;
}
char* inode_to_proc(char* inode) {
    struct dirent *de;
    DIR *dr = opendir("/proc");

    if (dr == NULL) {
        //printf("unable to open\n");
		return "-";
    }
    while( (de = readdir(dr)) != NULL){
        char* tmp_fd = malloc(64*sizeof(char));
        //printf("%s\n", de->d_name);
        sprintf(tmp_fd, "/proc/%s/fd", de->d_name);
        //traverse fd
        struct dirent *fd_de;
        DIR *fd_dr = opendir(tmp_fd);
        if(fd_dr == NULL) {
            free(tmp_fd);
            continue;
        }
        while((fd_de = readdir(fd_dr)) != NULL) {
            char* link_path = malloc(256*sizeof(char));
            char* target_path = malloc(256*sizeof(char));
            if (strcmp(fd_de->d_name, ".") ==0 || strcmp(fd_de->d_name, "..") == 0) {
                free(link_path);
                free(target_path);
                continue;
            } 
            sprintf(link_path, "%s/%s", tmp_fd, fd_de->d_name);
            int status = readlink(link_path, target_path, 256*sizeof(char));
            if( status == -1) {
                free(link_path);
                free(target_path);
                continue;
            }
            char* file_inode = malloc(12*sizeof(char));
            *(target_path+status) = '\0';
            sscanf(target_path, "socket:[%[^]s]", file_inode);
            if(strcmp(file_inode, "") != 0) {
                status = strcmp(file_inode, inode);
            }
            free(file_inode);
            free(link_path);
            free(target_path);
            if (status == 0) {
                char* pid = de->d_name;
                char* p_name = malloc(32*sizeof(char));
                char* res = malloc(64*sizeof(char));
                char* file_to_be_read = malloc(64*sizeof(char));
                // Read the proc/<pid>/comm to get p_name
                sprintf(file_to_be_read, "/proc/%s/comm", pid);
                FILE *fp;
                fp = fopen(file_to_be_read, "r");
                if (fp != NULL) {
                	char* buffer = malloc(64*sizeof(char));
                    fgets(buffer, 64, fp);
                    sscanf(buffer,"%s", p_name);
					free(buffer);
                }
                fclose(fp);
                // Read the proc/<pid>/cmdline to get parameters
                sprintf(file_to_be_read, "/proc/%s/cmdline", pid);
                fp = fopen(file_to_be_read, "r");
				int i = 0;
				char* buffer = malloc(128*sizeof(char));
                if (fp != NULL) {
                    fgets(buffer, 128, fp);
					while (*(buffer+i) != ' ' && *(buffer+i) > 0 ) {
						i++;
					}
                }
                fclose(fp);
                //
                sprintf(res, "%s/%s %s", pid, p_name, buffer+i+1);
                free(buffer);
                free(p_name);
                free(tmp_fd);
                closedir(fd_dr);
                closedir(dr);
                return res;
            }
        }
        closedir(fd_dr);
        free(tmp_fd);
    }
    closedir(dr);
    return "-";
}