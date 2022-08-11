#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>

#define MYPORT 8080 

// Assumption: any http request/response header will not exceed 4096 bytes.
#define MAX_BUFFER 4096

#define HTTP_RESPONSE_OK "200 OK\r\n"
#define CONTENT_LENGTH_FIELD "Content-Length:"
#define HEAD_CONTENT_SPLIT "\r\n\r\n"
#define LINE_END "\r\n"
#define GET "GET"
// support for two protocols
#define HTTP10 "HTTP/1.0"
#define HTTP11 "HTTP/1.1"

#define MAX_DELAY_IN_SELECT 5
// http code
#define RESPONSE_OK_CODE 200
#define RESPONSE_NOT_IMPLEMENTED_CODE 501
#define RESPONSE_BAD_REQUEST_CODE 400
#define RESPONSE_NOT_FOUND_CODE 404
#define RESPONSE_TIME_OUT_CODE 408

#define INVALID_END "/.."
#define MSG_NOT_IMPLEMENTED "HTTP/1.0 501 Not Implemented\r\n\r\n<html><body><h1>501 Not Implemented</h1></body></html>"
#define MSG_BAD_REQUEST "HTTP/1.0 400 Bad Request\r\n\r\n<html><body><h1>400 Bad Request</h1></body></html>"
#define MSG_NOT_FOUND "HTTP/1.0 404 Not Found\r\n\r\n<html><body><h1>404 Not Found</h1></body></html>"
#define MSG_TIME_OUT "HTTP/1.0 408 Request Timeout\r\n\r\n<html><body><h1>408 Request Timeout</h1></body></html>"
#define MSG_OK "HTTP/1.0 200 OK\r\nContent-Length: %d\r\n\r\n"
#define DYNAMIC_KEY "GET /?key="
#define DYNAMIC_KEY2 "/?key="
#define FLAG_DONE "DONE"
#define FLAG_NOT_FOUND "File Not Found"

#define MAXPENDING 50 // Maximum request, pass to listen()

#define DBADDR "127.0.0.1"
#define DBPORT 53004

/**
 * read from the socket fd.
 * if first_line is enabled and '\r\n' can be found in buf, return directly.
 * if read_content_length is enabled and HEAD_CONTENT_SPLIT or CONTENT_LENGTH_FIELD can be found in buf, return
 * directly. if read_split is enabled and HEAD_CONTENT_SPLIT can be found in buf, return directly. offset is an
 * input/output parameter, the result offset will be stored in offset. read_length: new-offset - old-offset. return:
 *  STATUS_NO_MORE_DATA:           there is no more data.
 *  STATUS_MORE_DATA_IN_FUTURE:    there are possible data.
 *  STATUS_READ_FAIL:              read failed
 * if there is any error during reading, exit directly.
 */
// read status
#define STATUS_NO_MORE_DATA 0
#define STATUS_MORE_DATA_IN_FUTURE 1
#define STATUS_READ_FAIL 2
int read_from_socket(int fd, char buf[MAX_BUFFER], int max_bytes, bool first_line, bool read_content_length,
                     bool read_split, int *offset, int *read_length);
/**
 * if there is any error during writing, exit directly.
 * return:
 *      true: send success
 *      false: send failure
 */

bool send_to_socket(int fd, const char *buf, int buf_len);

// process for a request for the client
void process_for_client_socket(int client_fd, const char *address);

int main() {
    int listen_fd, client_fd;
    struct sockaddr_in my_addr;
    struct sockaddr_in their_addr; /* client's address info */
    char dst[INET_ADDRSTRLEN];

    if ((listen_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket");
        exit(1);
    }

    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(MYPORT);
    my_addr.sin_addr.s_addr = INADDR_ANY; /* bind to all local interfaces */
    bzero(&(my_addr.sin_zero), 8);

    {
        // try to decrease the possibilities that a bind error occurs after restarting.
        int status = 1;
        setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &status, sizeof(int));
    }
    if (bind(listen_fd, (struct sockaddr *)&my_addr, sizeof(struct sockaddr)) < 0) {
        perror("bind");
        exit(1);
    }

    if (listen(listen_fd, MAXPENDING) < 0) {
        perror("listen");
        exit(1);
    }

    while (1) {
        socklen_t sin_size = sizeof(struct sockaddr_in);
        if ((client_fd = accept(listen_fd, (struct sockaddr *)&their_addr, &sin_size)) < 0) {
            perror("accept");
            continue;
        }

        inet_ntop(AF_INET, &(their_addr.sin_addr), dst, INET_ADDRSTRLEN);

        process_for_client_socket(client_fd, dst);

        fflush(stdout);  // update stdout
    }

    close(listen_fd);

    return 0;
}

int read_from_socket(int fd, char buf[MAX_BUFFER], int max_bytes, bool first_line, bool read_content_length,
                     bool read_split, int *poffset, int *pread_length) {
    int offset = *poffset;
    int read_length = 0;
    // do not overflow the buffer
    int next_read_status = STATUS_MORE_DATA_IN_FUTURE;
    if (offset < max_bytes) {
        // read at most left_bytes bytes.
        int left_bytes = max_bytes - offset;
        do {
            // check some flags
            if (first_line && strstr(buf, LINE_END)) {
                break;
            } else if (read_content_length && (strstr(buf, HEAD_CONTENT_SPLIT) || strstr(buf, CONTENT_LENGTH_FIELD))) {
                break;
            } else if (read_split && strstr(buf, HEAD_CONTENT_SPLIT)) {
                break;
            }
            ssize_t tmp = recv(fd, &(buf[offset]), left_bytes, 0);
            if (tmp == -1) {
                next_read_status = STATUS_READ_FAIL;
                break;
            } else if (tmp == 0) {
                next_read_status = STATUS_NO_MORE_DATA;
                break;
            } else {
                offset += tmp;
                left_bytes -= tmp;
                read_length += tmp;
            }
        } while (left_bytes > 0);

        *pread_length = read_length;
        *poffset = offset;
    }

    return next_read_status;
}

bool send_to_socket(int fd, const char *buf, int buf_len) {
    int offset = 0;
    while (buf_len > 0) {
        // multiple writes may be needed.
        ssize_t tmp = send(fd, buf + offset, buf_len, 0);
        if (tmp == -1) {
            return false;
        }

        offset += (int)tmp;
        buf_len -= (int)tmp;
    }
    return true;
}

int extract_request_parameters(char buf[MAX_BUFFER], char request_parameter[MAX_BUFFER], bool *is_static) {
    int status_code = RESPONSE_OK_CODE;
    char *first_line_end = 0;
    char *get_location = 0;
    char *key_location = 0;
    if ((key_location = strstr(buf, DYNAMIC_KEY)) == buf && (first_line_end = strstr(buf, LINE_END))) {
        // read the first line success. it is a dynamic request.
        (*is_static) = false;
    } else if ((get_location = strstr(buf, GET)) == buf && (first_line_end = strstr(buf, LINE_END))) {
        (*is_static) = true;
    } else {
        first_line_end = strstr(buf, LINE_END);
        status_code = RESPONSE_NOT_IMPLEMENTED_CODE;
    }
    if (first_line_end) {
        *first_line_end = 0;
    }
    if (status_code == RESPONSE_OK_CODE) {
        // read the first line success.
        // only support get.
        char *protocol_10 = strstr(buf, HTTP10);
        char *protocol_11 = strstr(buf, HTTP11);
        if ((protocol_10 && protocol_10 < first_line_end) || (protocol_11 && protocol_11 < first_line_end)) {
            // only care about the content between GET and protocol_10/protocol_11
            char copy_buf[MAX_BUFFER] = {0};
            memcpy(copy_buf, buf, MAX_BUFFER);
            if (protocol_10 && protocol_10 < first_line_end) {
                copy_buf[protocol_10 - (char *)buf] = 0;
            } else {
                copy_buf[protocol_11 - (char *)buf] = 0;
            }

            sscanf((char *)copy_buf + strlen(GET), "%s", request_parameter);
        } else {
            status_code = RESPONSE_NOT_IMPLEMENTED_CODE;
        }
    }
    return status_code;
}

int process_dynamic_for_client_socket(int client_fd, char request_parameter[MAX_BUFFER]) {
    int status_code = RESPONSE_OK_CODE;
    char *key_begin = strstr(request_parameter, DYNAMIC_KEY2) + strlen(DYNAMIC_KEY2);
    int len = strlen(key_begin);
    for (int i = 0; i < len; i++) {
        if (key_begin[i] == '+') {
            key_begin[i] = ' ';
        }
    }

    int udp_socket = 0;
    struct sockaddr_in their_addr;

    // One way to implement timeout is to make the UDP socket non-blocking, and use the "select()" system call to
    // determine when there is some data to be read.
    if ((udp_socket = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0)) < 0) {
        // treat this case as timeout
        status_code = RESPONSE_TIME_OUT_CODE;
    } else {
        their_addr.sin_family = AF_INET;
        their_addr.sin_port = htons(DBPORT);
        inet_pton(AF_INET, DBADDR, &their_addr.sin_addr);

        if (sendto(udp_socket, key_begin, strlen(key_begin), 0, (struct sockaddr *)&their_addr,
                   sizeof(struct sockaddr)) < 0) {
            // treat this case as timeout
            status_code = RESPONSE_TIME_OUT_CODE;
        } else {
            char read_buf[MAX_BUFFER] = {0};
            char *content = 0;
            int content_len = 0;
            while (1) {
                fd_set reading_sets;
                int sockets_count = udp_socket;
                FD_ZERO(&reading_sets);
                FD_SET(udp_socket, &reading_sets);
                sockets_count++;
                struct timeval timeout;
                timeout.tv_sec = MAX_DELAY_IN_SELECT;
                timeout.tv_usec = 0;
                if (select(sockets_count, &reading_sets, NULL, NULL, &timeout) > 0) {
                    if (FD_ISSET(udp_socket, &reading_sets)) {
                        ssize_t len = recvfrom(udp_socket, read_buf, MAX_BUFFER, 0, 0, 0);
                        if (len < 0) {
                            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                                // it is normal case.
                                continue;
                            } else {
                                // treat this case as timeout
                                status_code = RESPONSE_TIME_OUT_CODE;
                                break;
                            }
                        } else {
                            if (len == strlen(FLAG_DONE) && strncmp(FLAG_DONE, read_buf, len) == 0) {
                                break;
                            } else if (len == strlen(FLAG_NOT_FOUND) && strncmp(FLAG_NOT_FOUND, read_buf, len) == 0) {
                                status_code = RESPONSE_NOT_FOUND_CODE;
                                break;
                            }
                            content = realloc(content, content_len + (int)len);
                            if (content == NULL) {
                                // treat this case as timeout
                                status_code = RESPONSE_TIME_OUT_CODE;
                                break;
                            } else {
                                memcpy(content + content_len, read_buf, len);
                                content_len += len;
                            }
                        }
                    }
                } else {
                    // time out.
                    status_code = RESPONSE_TIME_OUT_CODE;
                    break;
                }
            }

            if (status_code == RESPONSE_OK_CODE) {
                {
                    // construct header.
                    int len = sprintf(read_buf, MSG_OK, (int)content_len);
                    // send header
                    send_to_socket(client_fd, read_buf, len);
                }
                if (content_len > 0) {
                    // send the entire content.
                    send_to_socket(client_fd, content, content_len);
                }
            }
            free(content);
        }
    }

    return status_code;
}

int process_static_for_client_socket(int client_fd, char request_parameter[MAX_BUFFER]) {
    int status_code = RESPONSE_OK_CODE;
    char path[MAX_BUFFER] = {0};
    // path process.
    if (request_parameter[0] != '/') {
        // The server should also check that the request URI (the part that comes after GET) starts with “/”
        status_code = RESPONSE_BAD_REQUEST_CODE;
    } else if (strstr(request_parameter, "/../")) {
        // the server should make sure that the request URI does not contain “/../”
        status_code = RESPONSE_BAD_REQUEST_CODE;
    } else {
        char *loc = strstr(request_parameter, INVALID_END);
        if (loc && loc[strlen(INVALID_END)] == 0) {
            // and it does not end with “/..”
            status_code = RESPONSE_BAD_REQUEST_CODE;
        }
    }

    struct stat s;
    if (status_code == RESPONSE_OK_CODE) {
        strcat(path, "./Webpage");
        strcat(path, request_parameter);
        int len = strlen(path);
        // If the request URI ends with “/”, the server should treat it as if there were “index.html”
        // appended to it.
        if (path[len - 1] == '/') {
            strcat(path, "index.html");
        } else {
            if (stat(path, &s) == 0) {
                // If the request URI is a directory, but does not have a “/” at the end, then you should
                // append “index.html” to it.
                if (S_ISDIR(s.st_mode)) {
                    strcat(path, "/index.html");
                }

            } else {
                // The server sends “404 Not Found” if it is unable to open the requested file.
                status_code = RESPONSE_NOT_FOUND_CODE;
            }
        }
    }

    if (status_code == RESPONSE_OK_CODE) {
        // read the file and return it to the client.
        if (stat(path, &s) == 0) {
            if (!(S_ISREG(s.st_mode))) {
                // it is not a regular file.
                status_code = RESPONSE_NOT_FOUND_CODE;
            }
        } else {
            status_code = RESPONSE_NOT_FOUND_CODE;
        }
        if (status_code == RESPONSE_OK_CODE) {
            FILE *input = fopen(path, "r");
            if (input) {
                char read_buf[MAX_BUFFER] = {0};
                {
                    // construct header.
                    int len = sprintf(read_buf, MSG_OK, (int)s.st_size);
                    // send header
                    send_to_socket(client_fd, read_buf, len);
                }
                {
                    // read the entire file and send it
                    size_t len = 0;
                    while ((len = fread(read_buf, 1, sizeof(read_buf), input))) {
                        send_to_socket(client_fd, read_buf, (int)len);
                    }
                }
            } else {
                status_code = RESPONSE_NOT_FOUND_CODE;
            }
        }
    }
    return status_code;
}

void process_for_client_socket(int client_fd, const char *address) {
    char buf[MAX_BUFFER] = {0};
    int offset = 0;
    int length = 0;
    int status = read_from_socket(client_fd, buf, MAX_BUFFER, true, false, false, &offset, &length);
    if (status != STATUS_READ_FAIL) {
        char request_parameter[MAX_BUFFER] = {0};
        bool is_static = true;

        int status_code = extract_request_parameters(buf, request_parameter, &is_static);

        if (status_code == RESPONSE_OK_CODE) {
            if (is_static == false) {
                status_code = process_dynamic_for_client_socket(client_fd, request_parameter);
            } else {
                status_code = process_static_for_client_socket(client_fd, request_parameter);
            }
        }
        if (status_code == RESPONSE_NOT_IMPLEMENTED_CODE) {
            send_to_socket(client_fd, MSG_NOT_IMPLEMENTED, strlen(MSG_NOT_IMPLEMENTED));
            printf("%s \"%s\" 501 Not Implemented\n", address, buf);
        } else if (status_code == RESPONSE_BAD_REQUEST_CODE) {
            send_to_socket(client_fd, MSG_BAD_REQUEST, strlen(MSG_BAD_REQUEST));
            printf("%s \"%s\" 400 Bad Request\n", address, buf);
        } else if (status_code == RESPONSE_NOT_FOUND_CODE) {
            send_to_socket(client_fd, MSG_NOT_FOUND, strlen(MSG_NOT_FOUND));
            printf("%s \"%s\" 404 Not Found\n", address, buf);
        } else if (status_code == RESPONSE_TIME_OUT_CODE) {
            send_to_socket(client_fd, MSG_TIME_OUT, strlen(MSG_TIME_OUT));
            printf("%s \"%s\" 408 Request Timeout\n", address, buf);
        } else {
            printf("%s \"%s\" 200 OK\n", address, buf);
        }
    }
    close(client_fd);
}
