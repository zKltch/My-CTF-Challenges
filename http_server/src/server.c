#define _GNU_SOURCE // for strcasestr
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h> // for mkdir
#include <time.h>
#include <unistd.h>

#define PORT 8080
#define BUFFER_SIZE 1073741824
#define UPLOAD_DIR "./uploads"
#define MAX_FILES 100 

typedef struct file_info {
  char filename[64];
  char *description;
  uint64_t file_size;
  char status; //
} file_info_t;

file_info_t uploaded_files[MAX_FILES];
int file_count = 0;

// large bin
typedef struct HuffmanTable {
  uint8_t table_id;
  char reserved_data[0x4f0]; 
} HuffmanTable;

typedef struct JpegParserState {
  HuffmanTable *huffman_tables[4];
} JpegParserState;


char *SOF;
int SOF_Allocated;

int process_jpeg_for_validation(char *data, int len);

// Forward declaration
void send_response(int client_sock, const char *status, const char *body);

// Extract header value

char *get_header_value(const char *query, const char *header) {
    char *pos = strcasestr(query, header);
    size_t len=0xf0;

    if (!pos)
        return NULL;
    
    pos += strlen(header);
    while (*pos == ' ' || *pos == ':')
        pos++;

    char *value = (char *)malloc(len + 1);
    if (!value)
        return NULL;
    memcpy(value, pos, 0xf0);
    value[len] = '\0';

    return value;
}

// url parameter
char *get_param(char *qs, const char *key) {
  if (!qs)
    return NULL;
  char *p = strstr(qs, key);
  if (!p)
    return NULL;
  p += strlen(key);
  if (*p != '=')
    return NULL;
  p++;
  char *end = strchr(p, '&');
  size_t len = end ? (size_t)(end - p) : strlen(p);
  char *v = malloc(len + 1);
  if (!v)
    return NULL;
  memcpy(v, p, len);
  v[len] = 0;
  return v;
}

// send_response 
void send_response(int client_sock, const char *status, const char *body) {
  char response[4096]; 
  int len = snprintf(response, sizeof(response),
                     "HTTP/1.1 %s\r\n"
                     "Content-Type: text/html; charset=utf-8\r\n"
                     "Content-Length: %zu\r\n"
                     "Connection: close\r\n" 
                     "\r\n"
                     "%s",
                     status, strlen(body), body);
  send(client_sock, response, len, 0);
}

void send_upload_form(int client_sock) {
  const char *html =
      "<!DOCTYPE html><html><head><title>File Upload</title></head>"
      "<body><h1>Upload File</h1>"
      "<form method='POST' enctype='multipart/form-data'>"
      "<input type='file' name='file' required><br><br>"
      "<input type='submit' value='Upload'></form></body></html>";
  send_response(client_sock, "200 OK", html);
}

char *find_boundary(const char *content_type) {
  char *boundary = strstr(content_type, "boundary=");
  if (boundary) {
    boundary += 9;
    while (*boundary == ' ' || *boundary == '"')
      boundary++;
    char *end = boundary;
    while (*end && *end != ' ' && *end != '"' && *end != '\r' && *end != '\n')
      end++;

    int len = end - boundary;
    char *result = malloc(len + 3); // "--" + boundary + null
    if (!result)
      return NULL;
    snprintf(result, len + 3, "--%.*s", len, boundary);
    return result;
  }
  return NULL;
}

void send_log_page(int client_sock) {
  char body[16384]; 
  char temp_row[2048];
  int offset = 0;

  offset += snprintf(
      body + offset, sizeof(body) - offset,
      "<!DOCTYPE html><html><head><title>Upload Log</title>"
      "<style>table,th,td{border:1px solid "
      "#666;border-collapse:collapse;padding:8px;} "
      "pre{background-color:#f0f0f0;padding:5px;word-wrap:break-word;}</"
      "style></head>"
      "<body><h1>Uploaded Files Log</h1>"
      "<table><th>Filename</th><th>Description</th><th>Size "
      "(bytes)</th><th>Status</th>");

  for (int i = 0; i < file_count; i++) {
    file_info_t *display_info = &uploaded_files[i];

    snprintf(temp_row, sizeof(temp_row),
             "<tr><td>%s</td><td>%s</td><td>%lu</td><td>%c</td></tr>",
             display_info->filename,
             display_info->description ? display_info->description : "N/A",
             display_info->file_size, display_info->status);

    offset += snprintf(body + offset, sizeof(body) - offset, "%s", temp_row);
  }
  // HTML footer
  offset +=
      snprintf(body + offset, sizeof(body) - offset,
               "</table><br><a href='/'>Upload another file</a></body></html>");

  send_response(client_sock, "200 OK", body);
}

int process_jpeg_for_validation(char *data, int len) {
  JpegParserState state = {0};
  SOF_Allocated=0;
  int i = 0;

  while (i < len - 4) {
    if ((unsigned char)data[i] == 0xFF) {
      unsigned char marker = (unsigned char)data[i + 1];

      // SOI (Start) and EOI (End) markers are standalone
      if (marker == 0xD8 || marker == 0xD9 || marker == 0x00) {
        i += 2;
        continue;
      }

      // All other markers have a 2-byte length field
      uint16_t segment_len =
          ((unsigned char)data[i + 2] << 8) | (unsigned char)data[i + 3];
      if (segment_len < 2 || (i + 2 + segment_len) > len) {
        if (SOF_Allocated)
        {
          free(SOF);
          SOF = NULL;
        }
        return 0;
      }
      char *segment_data = &data[i + 4];

      switch (marker) {
      case 0xC4: // DHT - Define Huffman Table
      {
        uint8_t table_id = (unsigned char)segment_data[0] & 0x0F;
        if (table_id >= 0 && table_id < 4) {
          if (state.huffman_tables[table_id] != NULL) {
            free(state.huffman_tables[table_id]);
          }

          state.huffman_tables[table_id] =
              (HuffmanTable *)malloc(sizeof(HuffmanTable));
          state.huffman_tables[table_id]->table_id = table_id;
        }
        break;
      }
      case 0xFE: // COM - Comment
      {
        if (segment_len > 2) {
          size_t comment_size = segment_len - 2;
          char *comment_data = malloc(comment_size);

          memcpy(comment_data, segment_data, comment_size);
          comment_data[comment_size] = '\0';

          free(comment_data);
        }
        break;
      }
      case 0xC0: // SOF0 - Start of Frame (Baseline DCT)
      {
        if (SOF_Allocated)
        {
          free(SOF);
          SOF = NULL;
          return 0;
        }

        SOF_Allocated=1;
        size_t info_size = segment_len - 2;
        if (info_size <= 0)
          break;

        SOF = malloc(info_size);
        if (!SOF)
          break;
        break;
      }

      case 0xDA: // SOS - Start of Scan
      {
        if (SOF_Allocated == 1)
        {
          free(SOF);
          SOF = NULL;
        }
        break;
      }
    }
      i += segment_len + 2; // Move to the next segment's start
    }
    else {
      i++;
    }
  }

  uint8_t valid = 0;
  // Final cleanup
  for (int j = 0; j < 4; j++) {
    if (state.huffman_tables[j] != NULL) {
      valid++;
      free(state.huffman_tables[j]);
    }
  }

    if (SOF_Allocated == 1)
    {
      free(SOF);
      SOF = NULL;
    }

  if (!valid)
    return 0;

  return 1;
}

void handle_file_upload(int client_sock, char *buffer, int total_len,
                        const char *boundary) {
  mkdir(UPLOAD_DIR, 0755);
  
  char *filename_start = memmem(buffer, total_len, "filename=\"", 10);
  if (!filename_start) {
    send_response(client_sock, "400 Bad Request", "<h1>No filename found</h1>");
    return;
  }

  filename_start += 10;
  char *filename_end = strchr(filename_start, '"');
  if (!filename_end) {
    send_response(client_sock, "400 Bad Request", "<h1>Invalid filename</h1>");
    return;
  }

  int filename_len = filename_end - filename_start;
  if (filename_len <= 0 || filename_len > 64) {
    send_response(client_sock, "400 Bad Request",
                  "<h1>Invalid filename length</h1>");
    return;
  }

  for (int i = 0; i < filename_len; i++) {
    if (filename_start[i] == '/') {
      send_response(client_sock, "400 Bad Request",
                    "<h1>Invalid characters in filename</h1>");
      return;
    }
  }
  char filename[256];
  snprintf(filename, sizeof(filename), "%s/%.*s", UPLOAD_DIR, filename_len,
           filename_start);

  char *data_start = strstr(filename_end, "\r\n\r\n");
  if (!data_start) {
    send_response(client_sock, "400 Bad Request",
                  "<h1>Invalid data format</h1>");
    return;
  }
  data_start += 4;

  // char *data_end = strstr(data_start, boundary);
  char *search_area = data_start;
  size_t search_len =
      total_len - (data_start - buffer); // Calculate the remaining length

  // Use memmem to find the boundary within that specific memory area
  char *data_end = memmem(search_area, search_len, boundary, strlen(boundary));

  if (!data_end) {
    send_response(client_sock, "400 Bad Request", "<h1>Invalid boundary</h1>");
    return;
  }

  if (data_end >= data_start + 2) {
    data_end -= 2;
  }

  int data_len = data_end - data_start;
  if (data_len < 0) {
    send_response(client_sock, "400 Bad Request",
                  "<h1>Invalid data length</h1>");
    return;
  }

  // check jpg file
  if (strstr(filename, ".jpg") || strstr(filename, ".jpeg")) {
    if (!process_jpeg_for_validation(data_start, data_len)) {
      send_response(client_sock, "400 Bad Request",
                    "<h1>Invalid .jpg format</h1>");
    }
  }
  FILE *fp = fopen(filename, "wb");
  if (!fp) {
    send_response(client_sock, "500 Internal Server Error",
                  "<h1>Failed to save file</h1>");
    return;
  }

  fwrite(data_start, 1, data_len, fp);
  fclose(fp);
  // log
  if (file_count < MAX_FILES) {

    file_info_t *info = &uploaded_files[file_count]; 

    info->file_size = data_len;
    info->status = 'S';

    strncpy(info->filename, filename_start, 64);
    if (filename_len < 64) {
      info->filename[filename_len] = '\0';
    }
    char *desc_header = get_header_value(buffer, "Description");
    if (desc_header) {
      info->description = desc_header; 
    } else {
      info->description =
          strdup("No description provided."); 
    }
    file_count++;
  }
  char success_msg[512];
  snprintf(success_msg, sizeof(success_msg),
           "<h1>Upload Successful!</h1><p>File saved: %.*s (%d bytes)</p><a "
           "href='/'>Upload another</a>",
           filename_len, filename_start, data_len);
  send_response(client_sock, "200 OK", success_msg);
}

void handle_request(int client_sock) {
  char *buffer = malloc(BUFFER_SIZE);
  if (!buffer) {
    send_response(client_sock, "500 Internal Server Error",
                  "<h1>Memory allocation failed</h1>");
    return;
  }

  int bytes_read = recv(client_sock, buffer, BUFFER_SIZE - 1, 0);

  if (bytes_read <= 0) {
    free(buffer);
    return;
  }
  long content_length = 0;
  char *cl_header = strcasestr(buffer, "Content-Length:");
  if (cl_header) {
    content_length = atol(cl_header + 15); 
  }

  if (content_length > BUFFER_SIZE - 1) {
    send_response(client_sock, "413 Payload Too Large",
                  "<h1>File Size Too Large</h1>");
    free(buffer);
    return;
  }
  // large cant be fully read
  char *body_start = strstr(buffer, "\r\n\r\n");
  if (body_start && content_length > 0) {
    body_start += 4; // Move pointer to the start of the body
    int header_len = body_start - buffer;
    long body_bytes_read = bytes_read - header_len;
    long bytes_remaining = content_length - body_bytes_read;

    while (bytes_remaining > 0 && bytes_read < BUFFER_SIZE - 1) {
      int bytes_read_now =
          recv(client_sock, buffer + bytes_read, bytes_remaining, 0);
      if (bytes_read_now <= 0) {
        break;
      }
      bytes_read += bytes_read_now;
      bytes_remaining -= bytes_read_now;
    }
  } // fix end
  buffer[bytes_read] = '\0';

  printf("Received %d bytes\n", bytes_read); 
  if (strncmp(buffer, "GET /log", 8) == 0) {
    send_log_page(client_sock);
  } else if (strncmp(buffer, "GET /", 5) == 0) {
    send_upload_form(client_sock);
  } else if (strncmp(buffer, "POST /", 6) == 0) {
    char *content_type = strstr(buffer, "Content-Type:");
    if (content_type) {
      char *line_end = strstr(content_type, "\r\n");
      if (line_end) {
        int original_char = *line_end;
        *line_end = '\0'; 

        char *boundary = find_boundary(content_type);
        *line_end = original_char; 

        if (boundary) {
          handle_file_upload(client_sock, buffer, bytes_read, boundary);
          free(boundary);
        } else {
          send_response(client_sock, "400 Bad Request",
                        "<h1>No boundary found</h1>");
        }
      }
    } else {
      send_response(client_sock, "400 Bad Request",
                    "<h1>No Content-Type header</h1>");
    }
  } else {
    send_response(client_sock, "405 Method Not Allowed",
                  "<h1>Method Not Allowed</h1>");
  }

  free(buffer);
}

int main() {
  int server_fd, new_socket;
  struct sockaddr_in address;
  int addrlen = sizeof(address);
  int opt = 1;

  if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
    perror("socket failed");
    exit(EXIT_FAILURE);
  }

  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
    perror("setsockopt");
    exit(EXIT_FAILURE);
  }

  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons(PORT);

  if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
    perror("bind failed");
    exit(EXIT_FAILURE);
  }

  if (listen(server_fd, 3) < 0) {
    perror("listen");
    exit(EXIT_FAILURE);
  }

  printf("Server listening at http://127.0.0.1:%d\n", PORT);

  while (1) {
    new_socket =
        accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen);
    if (new_socket < 0) {
      perror("accept");
      continue;
    }

    handle_request(new_socket);
    close(new_socket);
  }

  close(server_fd);
  return 0;
}
