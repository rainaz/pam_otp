#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>

#define CONFIG_MAX_CHAR 255


static char *action_configuration(const char *filename, const char *uname){

	// char config_line[CONFIG_MAX_CHAR];
	// FILE *config_file = fopen(argv[1], "r");
	// while(fgets(config_line, CONFIG_MAX_CHAR, config_file)){
		// printf("%s", config_line);
	// }

	return "fda";	

}

int main(int argc, char **argv){
	char tmp[255];
	snprintf(tmp, 255, "aaaaaaabcfg");
	printf("%s\n", strstr(tmp, "abc") + 1);
	char *a = strstr(tmp, "abc") + 1;
	if(strcmp(a, "bcfg") == 0 )printf("Yesy\n");
	return 0;
}
