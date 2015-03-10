#include "helper.h"
 
struct rng_server_conf{
	char *server_ip;
	int port;
	int method;
};
int get_random(int byte_num, int method, char *random, const char *server_ip, const int port) {
	int socket_desc;
	struct sockaddr_in server;
	char message[100];
	char *server_reply = (char *)malloc(byte_num + 100);
	socket_desc = socket(AF_INET , SOCK_STREAM , 0);
	if (socket_desc == -1) {
		syslog(LOG_ALERT, "pam_otp[%d] Could not create socket to %s:%d", getpid(), server_ip, port);
		return REMOTE_ERR_MESG;
	}

	server.sin_addr.s_addr = inet_addr(server_ip);
	server.sin_family = AF_INET;
	server.sin_port = htons(port);

	if (connect(socket_desc , (struct sockaddr *)&server , sizeof(server)) < 0) {
		syslog(LOG_ALERT, "pam_otp[%d] error connected to %s:%d", getpid(), server_ip, port);
		return REMOTE_ERR_MESG;
	}
	snprintf(message, sizeof(message), "%d:%d", byte_num, method);

	if(send(socket_desc , message , strlen(message) , 0) < 0) {
		syslog(LOG_ALERT, "pam_otp[%d] error sending message to %s:%d", getpid(), server_ip, port);
		return REMOTE_ERR_MESG;
	}
	syslog(LOG_ALERT, "pam_otp[%d] successfully sending message to %s:%d", getpid(), server_ip, port);

	if(recv(socket_desc, server_reply , byte_num + 100 , 0) < 0) {
		syslog(LOG_ALERT, "pam_otp[%d] receive failed from %s:%d", getpid(), server_ip, port);
		return REMOTE_ERR_MESG;
	}
	memcpy(random, server_reply, (int)strlen(server_reply) + 1);
	syslog(LOG_ALERT, "pam_otp[%d] received password \"%s\" from %s:%d", getpid(), random, server_ip, port);
	close(socket_desc);
	return 0;
}

char *action_configuration_v1(FILE *config_file, const char *uname){

	char *config_line = malloc(CONFIG_MAX_CHAR);
	char action_line[ACTION_MAX_CHAR];
	char *seperator;
	int len;
	if(config_file == NULL) 
		return NULL;

	while(fgets(config_line, CONFIG_MAX_CHAR, config_file)){
		seperator = strstr(config_line, ":");
		seperator++;	
		// printf("--------%d : %s -> %d\n", len, config_line, strlen(uname));
		if(strncmp(config_line, uname, seperator - 1 - config_line) == 0){
			len = strlen(config_line);
			fseek(config_file, -len, SEEK_CUR);
			return seperator;
		}
	}
	return NULL;	
}

void delete_line(FILE *file, const char *filename){
	int delete_pos = ftell(file);
	int line_len = 1;
	char tmp = fgetc(file);
	while(tmp != '\n' && tmp != EOF){
		line_len++;
		tmp = fgetc(file);
	}
	if(tmp == EOF){
		printf("END\n");
		line_len--;
	}
	fseek(file, 0, SEEK_END);
	int end_file = ftell(file);
	printf("%d %d %d", delete_pos, line_len, end_file);
	char *buff = (char *)malloc(end_file + 1);
	int pos = 0;
	rewind(file);
	while((buff[pos++] = fgetc(file)) != EOF)
	memmove(buff + delete_pos, buff + delete_pos + line_len, end_file - delete_pos - line_len);
	freopen(filename, "w", file);
	fwrite(buff, end_file - line_len, 1, file);
	fclose(file);
	free(buff);
}

char *get_password_if_avail(const char *filename, const char *uname, time_t living_time){
	/*
	 * uname $method$salt$hased num
	 */
	FILE *passwd_file = fopen(filename, "r");
	char *passwd_mem = action_configuration_v1(passwd_file, filename);
	char *passwd, *tmp; 
	tmp = strstr(passwd_mem, " ") + 1;
	*tmp = '\0';
	passwd = malloc(tmp - passwd);
	time_t time_created = atoi(tmp);
	return (time(NULL) - time_created > living_time)?NULL:tmp;
}

int server_configuration(const char *config_line, struct rng_server_conf *conf){
	// 127.0.0.1:8080$1
	char *colon, *dollar;
	int conf_size = strlen(config_line) + 2;
	char *conf_copy = (char *)malloc(conf_size);
	memcpy(conf_copy, config_line, conf_size);
	// colon = strstr(conf_copy, ":");
	if((colon = strstr(conf_copy, ":")) == NULL)
		return CONFIG_FILE_ERR;
	// dollar = strstr(conf_copy, "$");
	if((dollar = strstr(conf_copy, "$")) == NULL)
		 return CONFIG_FILE_ERR;
	*colon = '\0';
	colon++;

	*dollar = '\0';
	dollar++;
	conf->server_ip = conf_copy;
	conf->port = atoi(colon);
	conf->method = atoi(dollar);
	return CONFIG_FILE_GOOD;
	
}

static char *passwd_gen(char *valid_char,int passwd_len, int method){
	int seed, i;
	char *passwd = (char *)malloc(sizeof(char) * (passwd_len + 1));
	FILE *fp;
	switch(method){
		case(RNG_SERVER) :
			return "fdsa";

		default :
			fp = fopen("/dev/random", "r");
			if(fp ==NULL){
				syslog(LOG_ALERT, "pam_otp[%d] can't open random pseudo file", getpid());
				return NULL;
			}
			if(fread(&seed, sizeof(seed), 1, fp) == 0){
				syslog(LOG_ALERT, "pam_otp[%d] can't read random pseudo file", getpid());
				fclose(fp);
				return NULL;
			}
			fclose(fp);
			srandom(seed);
			for(i = 0; i < passwd_len; i++){
				passwd[i] = valid_char[random() % passwd_len];
			}
			passwd[i] = '\0';
			return passwd;
	}


}
