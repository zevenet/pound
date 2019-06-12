#include "pound_sync.h"
#include "svc.h"
#include <sys/epoll.h>
#include <syslog.h>
#define DEBUG_SSYN 0
#define MAX_EVENTS 10
#define EPOLL_TIMEOUT_MS 2000

int init_pound_sync() {
  char sock[200] ="";
  listen_mode = 0;
  strcat(sock,"/tmp/ssync_");
  strcat(sock,name);
  strcat(sock,".socket");
  sync_socket = sock;
  logmsg(LOG_ERR, "sync_thread; sync socket: %s", sync_socket);
  unlink(sync_socket);
  sync_listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (sync_listen_fd < 0) {
      logmsg(LOG_ERR, "sync_thread; socket() failed: %s", strerror(errno));
      return -1;
  }
  struct sockaddr_un serveraddr;
  memset(&serveraddr, 0, sizeof(serveraddr));
  serveraddr.sun_family = AF_UNIX;
  strcpy(serveraddr.sun_path, sync_socket);
  int res = bind(sync_listen_fd, (struct sockaddr *)&serveraddr,
                 SUN_LEN(&serveraddr));
  if (res < 0) {
      logmsg(LOG_ERR, "sync_thread; bind() failed: %s", strerror(errno));
      return -1;
    }
  res = listen(sync_listen_fd, 2);
  if (res < 0) {
      logmsg(LOG_ERR, "sync_thread; listen() failed: %s", strerror(errno));
      return -1;
    }
  return 0;
}

char *serialize(POUND_ACTION *action, unsigned int *out_size) {
  int i, size;
  int key_len = strlen(action->session_key);
  int content_len = strlen(action->session_content);
  int pkt_len = 6;
  if (action->action != SYNC_REQUEST) {
      pkt_len += sizeof(POUND_ACTION) + key_len;
      if (action->action == SESS_ADD || action->action == SESS_UPDATE ||
          action->action == SESS_WRITE)
        pkt_len += content_len;
    }
  *out_size = 0;
  char *outbuffer = (char *)calloc(pkt_len + 1, sizeof(char ));
  outbuffer[(*out_size)++] = 0xef;
  outbuffer[(*out_size)++] = 0xab;
  outbuffer[(*out_size)++] = 6; // packet type
  outbuffer[(*out_size)++] = 5; // packet len
  outbuffer[(*out_size)++] = 0; // packet len
  outbuffer[(*out_size)++] = (char)action->action;
  size = strlen(name);
  if (size > 0) {
      outbuffer[(*out_size)++] = size & 0xff;
      for (i = 0; i < size; i++)
        outbuffer[(*out_size)++] = name[i];
    }
  if (action - action != SYNC_REQUEST) {
      for (i = 0; i < 4; i++)
        outbuffer[(*out_size)++] = action->listener >> (8 * i);
      for (i = 0; i < 4; i++)
        outbuffer[(*out_size)++] = action->service >> (8 * i);
      for (i = 0; i < 4; i++)
        outbuffer[(*out_size)++] = action->backend >> (8 * i);

      size = strlen(action->session_key);
      if (size > 0) {
          outbuffer[(*out_size)++] = size & 0xff;
          for (i = 0; i < size; i++)
            outbuffer[(*out_size)++] = action->session_key[i];
        }

      if (action->action == SESS_ADD || action->action == SESS_UPDATE ||
          action->action == SESS_WRITE) {
          size = strlen(action->session_content);
          if (size > 0) {
              outbuffer[(*out_size)++] = size & 0xff;
              for (i = 0; i < size; i++)
                outbuffer[(*out_size)++] = action->session_content[i];
            }
          for (i = 0; i < 8; i++)
            outbuffer[(*out_size)++] = action->session_last_acc >> (8 * i);
        }
    }
  return outbuffer;
}

POUND_ACTION *deserialize(char *data, const int data_size, int *data_used) {

  int len, i,j,size,name_size;
  (*data_used) = 0;
  char header_1 = data[(*data_used)++];
  char header_2 = data[(*data_used)++];
  int message_type = data[(*data_used)++];
  len = data[(*data_used)++];
  len |= (((int)data[(*data_used)++]) << 8);
  if (data_size < len) {
      return NULL;
    }
  POUND_ACTION *action = (POUND_ACTION *)calloc(1, sizeof(POUND_ACTION));
  action->action = (ACTION_TYPE)data[(*data_used)++];

  //  logmsg(LOG_DEBUG, "sync_thread;   header: 0x%02x", header_1);
  //  logmsg(LOG_DEBUG, "sync_thread;   header: 0x%02x", header_2);
  //  logmsg(LOG_DEBUG, "sync_thread;   pkt typ: %d", message_type);
  //  logmsg(LOG_DEBUG, "sync_thread;   len: %d", len);
  //  logmsg(LOG_DEBUG, "sync_thread;   action: %d", (int)action->action);
  name_size = data[(*data_used)++] & 0xff;
  // logmsg(LOG_DEBUG, "sync_thread;   key size: %d", size);
  if (name_size > 0) {
      char farm_name[256] ="";
      for (i = 0; i < name_size; i++)
        farm_name[i] = data[(*data_used)++] & 0xff;
      ;
    }
  if (action->action != SYNC_REQUEST) {
      for (i = 0; i < 4; i++) {
          action->listener |= (((unsigned int)data[(*data_used)++]) & 0xff)
              << (8 * i);
          // logmsg(LOG_DEBUG, "sync_thread;   buffer[%d] = 0x%02x , listener[%i]=
          // %u",(*data_used)-1,data[(*data_used)-1],i, action->listener);
        }
      for (i = 0; i < 4; i++) {
          action->service |= (((unsigned int)data[(*data_used)++]) & 0xff)
              << (8 * i);
          // logmsg(LOG_DEBUG, "sync_thread;   buffer[%d] = 0x%02x , service[%i]=
          // %u",(*data_used)-1,data[(*data_used)-1],i, action->service);
        }
      for (i = 0; i < 4; i++) {
          action->backend |= (((unsigned int)data[(*data_used)++]) & 0xff)
              << (8 * i);
          // logmsg(LOG_DEBUG, "sync_thread;   buffer[%d] = 0x%02x , backend[%i]=
          // %u",(*data_used)-1,data[(*data_used)-1],i, action->backend);
        }

      size = data[(*data_used)++] & 0xff;
      // logmsg(LOG_DEBUG, "sync_thread;   key size: %d", size);
      if (size > 0) {
          action->session_key = (char *)calloc(size, sizeof(char));
          for (i = 0; i < size; i++)
            action->session_key[i] = data[(*data_used)++] & 0xff;
          ;
        }

      if (action->action == SESS_ADD || action->action == SESS_UPDATE ||
          action->action == SESS_WRITE) {
          size = data[(*data_used)++] & 0xff;
          // logmsg(LOG_DEBUG, "sync_thread;   content size: %d", size);
          if (size > 0) {
              action->session_content = (char *)calloc(size, sizeof(char));
              for (i = 0; i < size; i++)
                action->session_content[i] = data[(*data_used)++] & 0xff;
            }

          for (j = 0; j < 8; j++) {
              action->session_last_acc |=
                  (((unsigned long)data[(*data_used)++]) & 0xff) << (8 * j);
              // logmsg(LOG_DEBUG, "sync_thread;   buffer[%d] = 0x%02x , last_Acc[%d]=
              // %u",(*data_used)-1,data[(*data_used)-1],j, action->session_last_acc);
            }
        }
    }

  return action;
}

int send_action(POUND_ACTION *action) {
  if (sync_is_running == 0)
    return 0;
  int res = 0;
  int sent = 0;
  int count = 0;
  int size = 0;
  char *buffer = serialize(action, &size);
  if (size > 0) {
      pthread_mutex_lock(&send_lock);
      while (sent < size) {
          count = send(conn_sock, buffer + sent, size - sent, MSG_NOSIGNAL);
          if ((count == -1) && (errno == EWOULDBLOCK || errno == EAGAIN)) {
               usleep(5000);
               continue;
           }else if (count == (size - sent))
                break;
           else if (count < 0) {
//              if(count == EPIPE){
//                sync_is_running = 0;
//              }
              logmsg(LOG_ERR, "sync_thread; send() failed: %s", strerror(errno));
              res = -1;
              break;
            }else
              sent += count;
        }
  }
  free(buffer);
  pthread_mutex_unlock(&send_lock);
  return res;
}

void receive_task() {
  char buffer[65555*100];
  int buffer_size = 0;
  num_connections = 0;
  sync_is_running = 1;
  int i, count, fd, epfd, nfds = -1;

  struct epoll_event ev, events[MAX_EVENTS];

  epfd = epoll_create(MAX_EVENTS);

  if (epfd == -1) {
      logmsg(LOG_ERR, "sync_thread; epoll_create: %s", strerror(errno));
      return;
    }
  ev.events = EPOLLIN | EPOLLRDHUP | EPOLLERR; //| EPOLLET;
  ev.data.fd = sync_listen_fd;

  if (epoll_ctl(epfd, EPOLL_CTL_ADD, sync_listen_fd, &ev) == -1) {
      logmsg(LOG_ERR, "sync_thread; epoll_ctl: %s", strerror(errno));
      return;
    }

  while (1) {
      nfds = epoll_wait(epfd, events, MAX_EVENTS, EPOLL_TIMEOUT_MS);
      if (nfds < 0) {
          logmsg(LOG_ERR, "sync_thread; epoll_wait:  %s", strerror(errno));
          continue;
        }
      for (i = 0; i < nfds; ++i) {
          fd = events[i].data.fd;
          if (fd == sync_listen_fd) {
              if ((conn_sock = accept(fd, NULL, NULL)) > 0) {
                  int one = 1;
                  int flags, s;
                  flags = fcntl(fd, F_GETFL, 0);
                  if (flags == -1) {
                      logmsg(LOG_ERR,
                             "sync_thread; Error setting socket non-blocking, fcntl: %s",
                             strerror(errno));
                      continue;
                    }
                  flags |= O_NONBLOCK;
                  s = fcntl(fd, F_SETFL, flags);
                  if (s == -1) {
                      logmsg(LOG_ERR,
                             "sync_thread; Error setting socket non-blocking, fcntl: %s",
                             strerror(errno));
                      continue;
                    }
                  ev.events = EPOLLIN | EPOLLET;
                  ev.data.fd = conn_sock;
                  if (epoll_ctl(epfd, EPOLL_CTL_ADD, conn_sock, &ev) == -1) {
                      logmsg(LOG_ERR, "sync_thread; epoll_ctl: add: %s", strerror(errno));
                      continue;
                    }
                  logmsg(LOG_NOTICE, "sync_thread; connected sync client, fd: %d",
                         conn_sock);
                  num_connections++;
                  listen_mode = 0;
                }
              if (conn_sock == -1) {
                  if (errno != EAGAIN && errno != ECONNABORTED && errno != EPROTO &&
                      errno != EINTR) {
                      logmsg(LOG_ERR, "sync_thread; accept(): %s", strerror(errno));
                    }
                  continue;
               }
              continue;
            } else if (events[i].events & EPOLLIN) {
              memset(buffer + buffer_size, 0,
                     sizeof (buffer) - buffer_size);
              // Incoming data, read and parse
              if ((count = recv(fd, buffer + buffer_size,
                                sizeof(buffer) - buffer_size, MSG_NOSIGNAL)) > 0) {

                  buffer_size += count;
                }

              if (count == -1 && errno != EAGAIN) {
                  buffer_size = 0;
                  logmsg(LOG_ERR, "sync_thread; recv() failed: %s", strerror(errno));
                  continue;
                } else if (count == 0) {
                  buffer_size = 0;
                  num_connections =0;
                  logmsg(LOG_NOTICE, "sync_thread; peer connection closed: %s",
                         strerror(errno));
                  if (epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL) < 0)
                    logmsg(LOG_ERR, "sync_thread; epoll_ctl() failed: %s",
                           strerror(errno));
                  close(fd);
                  continue;
              }
              if (buffer_size > 0) {
                  while (buffer_size > 0) {
                      int buffer_used = 0;
                      POUND_ACTION *action =
                          deserialize(buffer, buffer_size, &buffer_used);
                      if (action != NULL) {
                          if ((sizeof (buffer) - buffer_size) >= buffer_used ) {
                              buffer_size -= buffer_used;
                              memmove(buffer, buffer + buffer_used, sizeof (buffer) - buffer_size);
                            }
                          if (process_action(action)) {
                              free_action(action);
                           }
                        } else {
                          break;
                        }
                    }
                }
            } else if (events[i].events & EPOLLOUT) {
              continue;
            }
        }
    }
  logmsg(LOG_ERR, "thread_sync: thread closing!");
  sync_is_running = 0;
  num_connections = 0;
  close(sync_listen_fd);
  close(epfd);
}

void start_sync_thr(void) {
  int rc;
  rc = pthread_create(&receive_thread, NULL, receive_task, NULL);
  rc = pthread_detach(receive_thread);
}

void free_action(POUND_ACTION *action) {
  if (action - action != SYNC_REQUEST) {
       //logmsg(LOG_NOTICE, "thread_sync: Freeing session key");
      free(action->session_key);
      if (action->action == SESS_ADD || action->action == SESS_UPDATE ||
          action->action == SESS_WRITE) {
          // logmsg(LOG_NOTICE, "thread_sync: Freeing session content");
          free(action->session_content);
        }
    }
  free(action);
}

int process_action(POUND_ACTION *action) {
  LISTENER *lstn;
  SERVICE *svc;
  BACKEND *be;
  int i, ret_val;


  char str[1000] = "sync_thread: ACTION: ";
  if (action != NULL) {
      switch (action->action) {
        case SYNC_REQUEST:
          strcat(str, "SYNC_REQUEST");
          listen_mode = 1;
          handle_sync_request(action->fd);
          break;
        case SESS_ADD:
          strcat(str, " SESS_ADD");
          break;
        case SESS_UPDATE:
          strcat(str, "SESS_UPDATE");
          break;
        case SESS_DELETE:
          strcat(str, "SESS_DELETE");
          break;
        case SESS_WRITE: {
            int tmp = listen_mode;
            listen_mode = 0;
            strcat(str, "SESS_WRITE ");

            sprintf(str + strlen(str), " L[%u]", action->listener);
            sprintf(str + strlen(str), " S[%u]", action->service);
            sprintf(str + strlen(str), " B[%u]", action->backend);
            strcat(str, " ");
            strcat(str, action->session_key);
            strcat(str, " [");
            sprintf(str + strlen(str), " %lu", action->session_last_acc);
            strcat(str, "] >> ");
            strcat(str, action->session_content);

            for (i = 0, lstn = listeners; lstn && i < (int)action->listener;
                 i++, lstn = lstn->next)
              ;
            if (lstn == NULL) {
                logmsg(LOG_ERR, "thread_sync: no listener found");
                listen_mode = tmp;
                return -1;
              }
            svc = lstn->services;
            for (i = 0; svc && i < (int)action->service; i++, svc = svc->next)
              if (svc == NULL) {
                  logmsg(LOG_ERR, "thread_sync: no service found");
                  listen_mode = tmp;
                  return -1;
                }
            for (i = 0, be = svc->backends; be && i < (int)action->backend;
                 i++, be = be->next);
            if (be == NULL) {
                logmsg(LOG_ERR, "thread_sync: no backend found");
                listen_mode = tmp;
                return -1;
              }
            if (ret_val = pthread_mutex_lock(&svc->mut))
              logmsg(LOG_WARNING, "thr_control() add session lock: %s",
                     strerror(ret_val));
            t_add(svc, action->session_key, &be, sizeof(be),
                  action->session_last_acc);
            if (ret_val = pthread_mutex_unlock(&svc->mut))
              logmsg(LOG_WARNING, "thr_control() add session unlock: %s",
                     strerror(ret_val));

          listen_mode = tmp;
          }
          break;
        case BCK_ADD:
          strcat(str, "BCK_ADD");
          break;
        case BCK_DELETE:
          strcat(str, "BCK_DELETE");
          break;
        case BCK_UPDATE:
          strcat(str, "BCK_UPDATE");
          break;
        default:
          strcat(str, "nothing to process");
          break;
        }

     logmsg(LOG_NOTICE,"%s", str);

    } else {
      logmsg(LOG_ERR, "sync_thread; Error processing data");
    }
  return 1;
}

void notify(ACTION_TYPE action, int listener, int service,
            char *key, void *content, unsigned int last_access) {
  if (listen_mode == 0 || sync_is_running == 0 || num_connections < 1)
    return;

  BACKEND *bep;
  memcpy(&bep, content, sizeof(bep));
  POUND_ACTION to_send;
  to_send.action = action;
  to_send.listener = listener;
  to_send.service = service;
  to_send.backend = bep->key_id;
  to_send.session_key = key;
  char tmp[200];
  addr2str(tmp, 200 - 1, &(bep->addr), 1);
  to_send.session_content = tmp;
  to_send.session_last_acc = last_access;
#if DEBUG_SSYNN
  char str[1000] = "sync_thread: ";
  switch (to_send.action) {
    case SYNC_REQUEST:
      strcat(str, "SYNC_REQUEST");
      break;
    case SESS_ADD:
      strcat(str, " SESS_ADD");
      break;
    case SESS_UPDATE:
      strcat(str, "SESS_UPDATE");
      break;
    case SESS_DELETE:
      strcat(str, "SESS_DELETE");
      break;
    case BCK_ADD:
      strcat(str, "BCK_ADD");
      break;
    case BCK_DELETE:
      strcat(str, "BCK_DELETE");
      break;
    case BCK_UPDATE:
      strcat(str, "BCK_UPDATE");
      break;
    default:
      strcat(str, "nothing to process");
      break;
    }

  sprintf(str + strlen(str), " L[%u]", to_send.listener);
  sprintf(str + strlen(str), " S[%u]", to_send.service);
  sprintf(str + strlen(str), " B[%u]", to_send.backend);
  strcat(str, " ");
  strcat(str, to_send.session_key);
  strcat(str, " [");
  sprintf(str + strlen(str), " %lu", to_send.session_last_acc);
  strcat(str, "] >> ");
  strcat(str, to_send.session_content);
  logmsg(LOG_ERR,"[%s:%d]%s",__FILE__,__LINE__, str);
#endif
  send_action(&to_send);
}

void set_objects_key_id() {
  LISTENER *lstn;
  SERVICE *svc;
  BACKEND *be;
  int n_listn, n_svc, n_bck;
  n_listn = 0;
  n_svc = 0;
  n_bck = 0;
  for (lstn = listeners; lstn; lstn = lstn->next) {
      lstn->key_id = n_listn++;
      n_svc = 0;
      //logmsg(LOG_DEBUG, "sync_thread; Set id listener: %d", lstn->key_id);
      for (svc = lstn->services; svc; svc = svc->next) {
          svc->key_id = n_svc++;
          svc->listener_key_id = lstn->key_id;
          n_bck = 0;
          //logmsg(LOG_DEBUG, "sync_thread:   Set id Service: %d", svc->key_id);
          //logmsg(LOG_DEBUG, "sync_thread:   Set id Service_lis: %d",
          //       svc->listener_key_id);
          for (be = svc->backends; be; be = be->next) {
              be->key_id = n_bck++;
              //logmsg(LOG_DEBUG, "sync_thread;        Set id backend: %d", be->key_id);
            }
        }
    }
}


void handle_sync_request(int fd)
{
  LISTENER *lstn;
  SERVICE *svc;
  TABNODE     sess;
  int n_listn, n_svc, n_bck;
  n_listn = 0;
  n_svc = 0;
  n_bck = 0;
  memset(&sess, 0, sizeof(sess));
  sess.content = NULL;
  for (lstn = listeners; lstn; lstn = lstn->next) {
      lstn->key_id = n_listn++;
      n_svc = 0;
      for (svc = lstn->services; svc; svc = svc->next) {
          svc->key_id = n_svc++;
          svc->listener_key_id = lstn->key_id;
          n_bck = 0;
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
          LHM_lh_doall_arg(TABNODE, svc->sessions,t_send_arg, SERVICE, svc);
#else
          lh_doall_arg(svc->sessions, LHASH_DOALL_ARG_FN(t_send_arg), &svc);
#endif
        }
    }
}

static void
t_send_arg(TABNODE *t, SERVICE* srv)
{
  notify( SESS_ADD, srv->listener_key_id, srv->key_id,
          t->key,t->content, (unsigned int)(t->last_acc));
  return;
}

void stop_session_sync()
{
  sync_is_running = 0;
  close(sync_listen_fd);
  unlink(sync_socket);
}
