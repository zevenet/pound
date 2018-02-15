#ifndef POUND_SYNC_H
#define POUND_SYNC_H
#include "pound.h"
#include "pound_sync_enum.h"

typedef struct _pound_action {
  int fd;
  ACTION_TYPE action;
  unsigned int listener;
  unsigned int service;
  unsigned int backend;
  char *session_key;
  char *session_content;
  unsigned long session_last_acc;
} POUND_ACTION;

static int num_connections;
static int conn_sock;
static int sync_listen_fd;
static volatile pthread_mutex_t send_lock;
static pthread_t receive_thread, sync_thread;
static volatile int sync_is_running;
static volatile int listen_mode;
char *serialize(POUND_ACTION *action, unsigned int *out_size);
POUND_ACTION *deserialize(char *data, const int data_size, int *data_used);
void free_action(POUND_ACTION *action);
int process_action(POUND_ACTION *action);
int init_pound_sync(void);
int send_action(POUND_ACTION *action);
void set_objects_key_id();
static void t_send_arg(TABNODE *t, SERVICE *srv);
void handle_sync_request(int fd);
void notify(ACTION_TYPE action, int listener, int service, char *key,
            void *content, unsigned int last_access);
void receive_task();
void start_sync_thr(void);
void stop_session_sync(void);
#endif
