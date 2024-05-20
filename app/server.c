#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#define BUFFER_SIZE 4096


struct HttpRequest {
    char method[10];
    char path[100];
    char protocol[20];
	char user_agent[BUFFER_SIZE];
};

char *resp_200 = "HTTP/1.1 200 OK\r\n";
char *resp_404 = "HTTP/1.1 404 Not Found\r\n\r\n";

void initHttpRequest(struct HttpRequest *request, char *req_buffer);
void initUserAgent(struct HttpRequest *request, char *req_buffer);
void processResponse(struct HttpRequest *request, int client);
int serverEcho(struct HttpRequest *request, int client);
int requestUserAgent(struct HttpRequest *request, int client);
char *writeResponse(char *type, char *response_body);

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

	struct HttpRequest request;
	char req_buffer[BUFFER_SIZE] = {0};
	int bytes_received = recv(client, req_buffer, sizeof(req_buffer), 0);

	printf("---> %s\n", req_buffer);
	initHttpRequest(&request, req_buffer);
	processResponse(&request, client);

	close(server_fd);

	return 0;
}


void initHttpRequest(struct HttpRequest *request, char *req_buffer) {


	char *token = NULL;
	char *rest = req_buffer;
	char *req_body[3] = {NULL};
	int i = 0;

	initUserAgent(request, req_buffer);

	while ((token = strtok_r(rest, " ", &rest))){
		req_body[i++] = token;
		if (i >= 3)
			break;
	}


    strncpy(request->method, req_body[0], sizeof(request->method)-1);
    strncpy(request->path, req_body[1], sizeof(request->path)-1);
    strncpy(request->protocol, req_body[2], sizeof(request->protocol)-1);
    request->method[sizeof(request->method)-1] = '\0';
    request->path[sizeof(request->path)-1] = '\0';
    request->protocol[sizeof(request->protocol)-1] = '\0';
}

void initUserAgent(struct HttpRequest *request, char *req_buffer) {
	
	char *token = NULL;
	char *rest = req_buffer;
	char *req_body[4] = {NULL};
	char *user_agent[2] = {NULL};
	
	int i = 0;
	while ((token = strtok_r(rest, "\r\n", &rest))){
		req_body[i++] = token;
		if (i >= 4)
			break;
	}

	
	token = NULL;
	rest = req_body[3];
	i = 0;

	while ((token = strtok_r(rest, ": ", &rest))){
		user_agent[i++] = token;
		if (i >= 2)
			break;
	}

	int user_agent_header = strcmp(user_agent[0], "User-Agent");

	if ( user_agent_header != 0){
		printf("EMPTY AGNET");
		strncpy(request->user_agent, "no-user-agent", sizeof(request->user_agent)-1);
	}
	else{
		strncpy(request->user_agent, user_agent[1], sizeof(request->user_agent)-1);
	}

	request->user_agent[sizeof(request->user_agent)-1] = '\0';
}

void processResponse(struct HttpRequest *request, int client){
	
	int get_method = strcmp(request->method, "GET");
	int path = strcmp(request->path, "/");

	if (get_method == 0)
	{

		if (path == 0){
			char buffer_resp_200[BUFFER_SIZE];
			sprintf(buffer_resp_200, "%s\r\n", resp_200);
			send(client, buffer_resp_200, strlen(buffer_resp_200),0);
			return;
		}
	
		else if ( serverEcho(request, client) != 1 ){
			requestUserAgent(request, client);
		}
		else{
			send(client, resp_404, strlen(resp_404),0);
		}
	
	}
}

int serverEcho(struct HttpRequest *request, int client){
	char *token = NULL;
	char *rest = request->path;
	char *echo_path[2] = {NULL};
	int i = 0;
	while ((token = strtok_r(rest, "/", &rest))){
		echo_path[i++] = token;
		if (i >= 2)
			break;
	}

	int echo = strcmp(echo_path[0], "echo");

	if (echo == 0){
		char *echo_response = writeResponse("text/plain", echo_path[1]);

		if (echo_response != NULL){
			send(client, echo_response, strlen(echo_response),0);
			free(echo_response);
		}

		return 1; //server echo success
	}
	

	return 0; //server echo 404

}

int requestUserAgent(struct HttpRequest *request, int client){
	char *token = NULL;
	char *rest = request->path;
	char *user_agent_path[1] = {NULL};
	int i = 0;
	while ((token = strtok_r(rest, "/", &rest))){
		user_agent_path[i++] = token;
		if (i >= 1)
			break;
	}

	int user_agent = strcmp(user_agent_path[0], "user-agent");
	if (user_agent == 0){
		char *user_agent_response = writeResponse("text/plain", request->user_agent);

		if (user_agent_response != NULL){
			send(client, user_agent_response, strlen(user_agent_response),0);
			free(user_agent_response);
		}
		else{
			send(client, resp_404, strlen(resp_404),0);
		}

		return 1;
	}

	return 0;
}

char *writeResponse(char *type, char *response_body){

	if (response_body == NULL){
		return NULL;
	}

	char *buffer = (char *)malloc(BUFFER_SIZE);

	if( buffer == NULL ){
		printf("SERVER ERROR");
		return NULL;
	}

	if (strcmp(type, "text/plain") == 0){
		size_t body_len = strlen(response_body);
		size_t len = 0;

		if (body_len > 0){
			len = snprintf(buffer, BUFFER_SIZE,"%sContent-Type: text/plain\r\nContent-Length: %zu\r\n\r\n%s",resp_200, body_len, response_body);
		}
		
		if (len < 0 || len >= BUFFER_SIZE) {
			printf("SERVER ERROR");
			free(buffer);
			return NULL;
		}
	}

	return buffer;
}
