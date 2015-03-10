#define CONFIG_MAX_CHAR 255
#define PROMPT_MAX_CHAR 127
#define ACTION_MAX_CHAR 255

#define REMOTE_ERR_MESG 99
#define REMOTE_SUC_MESG 0

#define LINUX_RANDOM 3
#define RNG_SERVER 4

#define CONFIG_FILE_ERR 12
#define CONFIG_FILE_GOOD 11

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>

#include <crypt.h>
#include<sys/socket.h>
#include<arpa/inet.h> 

struct rng_server_conf{
	char *server_ip;
	int port;
	int method;
};
int get_random(int byte_num, int method, char *random, const char *server_ip, const int port);
char *action_configuration_v1(FILE *config_file, const char *uname);
void delete_line(FILE *file, const char *filename);
char *get_password_if_avail(const char *filename, const char *uname, time_t living_time);
int server_configuration(const char *config_line, struct rng_server_conf *conf);
static char *passwd_gen(char *valid_char,int passwd_len, int method);
