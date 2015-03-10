#include<stdio.h>
#include<sys/socket.h>
#include<arpa/inet.h>
 
int main(int argc , char *argv[])
{
    int socket_desc , new_socket , c;
    struct sockaddr_in server , client;
     
	char *message;
	char header[100];
    //Create socket
    socket_desc = socket(AF_INET , SOCK_STREAM , 0);
    if (socket_desc == -1)
    {
        printf("Could not create socket");
    }
     
    //Prepare the sockaddr_in structure
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons( 8888 );
     
    //Bind
    if( bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0)
    {
        printf("bind failed");
    }
    printf("bind done");
     
    //Listen
    listen(socket_desc , 9);
     
    //Accept and incoming connection
    printf("Waiting for incoming connections...");
    c = sizeof(struct sockaddr_in);

	while((new_socket = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c))){
		printf("Connection accepted");
		recv(new_socket, header, 100, 0);
										 
		// Reply to the client

		message = malloc(100);
		printf("%s\n", header);
		snprintf(message, 100, "%s", header);
		write(new_socket , message , strlen(message));
	}

	if (new_socket<0) {
		perror("accept failed");
		return 1;
	}

	return 0;
}
