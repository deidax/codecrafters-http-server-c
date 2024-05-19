#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#define BUFFER_SIZE 4096


struct HttpResponse {
    char method[10];
    char path[100];
    char protocol[20];
};

char *resp_200 = "HTTP/1.1 200 OK\r\n\r\n";
char *resp_404 = "HTTP/1.1 404 Not Found\r\n\r\n";

void initHttpResponse(struct HttpResponse *response, char *req_buffer);
void processResponse(struct HttpResponse *response, int client);

int main() {
	// Disable output buffering
	setbuf(stdout, NULL);

	// You can use print statements as follows for debugging, they'll be visible when running tests.
	printf("Logs from your program will appear here!\n");

	// Uncomment this block to pass the first stage
	//
	int server_fd, client_addr_len;
	struct sockaddr_in client_addr;
	
	server_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (server_fd == -1) {
		printf("Socket creation failed: %s...\n", strerror(errno));
		return 1;
	}
	
	// Since the tester restarts your program quite often, setting REUSE_PORT
	// ensures that we don't run into 'Address already in use' errors
	int reuse = 1;
	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) < 0) {
		printf("SO_REUSEPORT failed: %s \n", strerror(errno));
		return 1;
	}
	
	struct sockaddr_in serv_addr = { .sin_family = AF_INET ,
									 .sin_port = htons(4221),
									 .sin_addr = { htonl(INADDR_ANY) },
									};
	
	if (bind(server_fd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) != 0) {
		printf("Bind failed: %s \n", strerror(errno));
		return 1;
	}
	
	int connection_backlog = 5;
	if (listen(server_fd, connection_backlog) != 0) {
		printf("Listen failed: %s \n", strerror(errno));
		return 1;
	}
	
	printf("Waiting for a client to connect...\n");
	client_addr_len = sizeof(client_addr);
	
	int client = accept(server_fd, (struct sockaddr *) &client_addr, &client_addr_len);
	printf("Client connected\n");

	struct HttpResponse response;
	char req_buffer[BUFFER_SIZE] = {0};
	int bytes_received = recv(client, req_buffer, sizeof(req_buffer), 0);
	
	initHttpResponse(&response, req_buffer);
	processResponse(&response, client);

	close(server_fd);

	return 0;
}


void initHttpResponse(struct HttpResponse *response, char *req_buffer) {
	char *token = NULL;
	char *rest = req_buffer;
	char *req_body[3] = {NULL};
	int i = 0;
	while ((token = strtok_r(rest, " ", &rest))){
		req_body[i++] = token;
		if (i >= 3)
			break;
	}

    strncpy(response->method, req_body[0], sizeof(response->method)-1);
    strncpy(response->path, req_body[1], sizeof(response->path)-1);
    strncpy(response->protocol, req_body[2], sizeof(response->protocol)-1);
    response->method[sizeof(response->method)-1] = '\0';
    response->path[sizeof(response->path)-1] = '\0';
    response->protocol[sizeof(response->protocol)-1] = '\0';
}

void processResponse(struct HttpResponse *response, int client){
	
	int get_method = strcmp(response->method, "GET");
	int path = strcmp(response->path, "/");

	if (get_method == 0){
		if (path == 0){
			send(client, resp_200, strlen(resp_200),0);
		}
		else{
			send(client, resp_404, strlen(resp_404),0);
		}
	}
}