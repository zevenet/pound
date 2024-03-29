
/*
 * Pound - the reverse-proxy load-balancer
 * Copyright (C) 2002-2010 Apsis GmbH
 *
 * This file is part of Pound.
 *
 * Pound is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * Pound is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Contact information:
 * Apsis GmbH
 * P.O.Box
 * 8707 Uetikon am See
 * Switzerland
 * EMail: roseg@apsis.ch
 */

#include    "pound.h"

/* HTTP error replies */
static char *h500 = "500 Internal Server Error",
  *h501 = "501 Not Implemented",
  *h503 = "503 Service Unavailable",
  *h400 = "400 Bad Request",
  *h414 = "414 Request URI too long", *h403 = "403 Request forbidden";

static char *err_response =
  "HTTP/1.0 %s\r\nContent-Type: text/html\r\nContent-Length: %d\r\nExpires: now\r\nPragma: no-cache\r\nCache-control: no-cache,no-store\r\n\r\n%s";

/*
 * Reply with an error
 */
static void err_reply(BIO * const c, const char *head, const char *txt)
{
  BIO_printf(c, err_response, head, strlen(txt), txt);
  BIO_flush(c);
  return;
}

/*
 * Reply with a redirect
 */
static void redirect_reply(BIO * const c, const char *url, const int code)
{
  char rep[MAXBUF], cont[MAXBUF], *code_msg;
  int i, j;

  switch (code) {
    case 301:
      code_msg = "Moved Permanently";
      break;
    case 307:
      code_msg = "Temporary Redirect";
      break;
    default:
      code_msg = "Found";
      break;
  }
  /*
   * Make sure to return a safe version of the URL (otherwise CSRF becomes a possibility)
   */
  snprintf(cont, sizeof(cont),
           "<html><head><title>Redirect</title></head><body><h1>Redirect</h1><p>You should go to <a href=\"%s\">%s</a></p></body></html>",
           url, url);
  snprintf(rep, sizeof(rep),
           "HTTP/1.0 %d %s\r\nLocation: %s\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n",
           code, code_msg, url, strlen(cont));
  BIO_write(c, rep, strlen(rep));
  BIO_write(c, cont, strlen(cont));
  BIO_flush(c);
  return;
}

/*
 * Read and write some binary data
 */
static int
copy_bin(BIO * const cl, BIO * const be, LONG cont, LONG * res_bytes,
         const int no_write)
{
  char buf[MAXBUF];
  int res;

  while (cont > L0) {
    if ((res = BIO_read(cl, buf, cont > MAXBUF ? MAXBUF : cont)) < 0)
      return -1;
    else if (res == 0)
      return -2;
    if (!no_write)
      if (BIO_write(be, buf, res) != res)
        return -3;
    cont -= res;
    if (res_bytes)
      *res_bytes += res;
  }
  if (!no_write)
    if (BIO_flush(be) != 1)
      return -4;
  return 0;
}

/*
 * Get a "line" from a BIO, strip the trailing newline, skip the input stream if buffer too small
 * The result buffer is NULL terminated
 * Return 0 on success
 */
static int
get_line(BIO * const in, char *const buf, const int bufsize, int *out_line_size)
{
  char tmp;
  int i, n_read;

//    memset(buf, 0, bufsize);
  *out_line_size = 0;
  for (n_read = 0;;)
    switch (BIO_gets(in, buf + n_read, bufsize - n_read - 1)) {
      case -2:
        /* BIO_gets not implemented */
        return -1;
      case 0:
      case -1:
        return 1;
      default:
        for (i = n_read; i < bufsize && buf[i]; i++)
          if (buf[i] == '\n' || buf[i] == '\r') {
            buf[i] = '\0';
            *out_line_size = i;
            return 0;
          }
        if (i < bufsize) {
          n_read = i;
          continue;
        }
        logmsg(LOG_NOTICE, "(%lx) line too long: %s", pthread_self(), buf);
        /* skip rest of "line" */
        tmp = '\0';
        while (tmp != '\n')
          if (BIO_read(in, &tmp, 1) != 1)
            return 1;
        break;
    }
  return 0;
}

/*
 * Strip trailing CRLF
 */
static int strip_eol(char *lin)
{
  while (*lin)
    if (*lin == '\n' || (*lin == '\r' && *(lin + 1) == '\n')) {
      *lin = '\0';
      return 1;
    } else
      lin++;
  return 0;
}

/*
 * Copy chunked
 */
static int
copy_chunks(BIO * const cl, BIO * const be, LONG * res_bytes,
            const int no_write, const LONG max_size)
{
  char buf[MAXBUF];
  LONG cont, tot_size;
  regmatch_t matches[2];
  int res, line_len = 0;

  for (tot_size = 0L;;) {
    if ((res = get_line(cl, buf, MAXBUF, &line_len)) < 0) {
      logmsg(LOG_NOTICE, "(%lx) chunked read error: %s", pthread_self(),
             strerror(errno));
      return -1;
    } else if (res > 0)
      /* EOF */
      return 0;
    if (!regexec(&CHUNK_HEAD, buf, 2, matches, 0))
      cont = STRTOL(buf, NULL, 16);
    else {
      /* not chunk header */
      logmsg(LOG_NOTICE, "(%lx) bad chunk header <%s>: %s", pthread_self(), buf,
             strerror(errno));
      return -2;
    }
    if (!no_write)
      if (BIO_printf(be, "%s\r\n", buf) <= 0) {
        logmsg(LOG_NOTICE, "(%lx) error write chunked: %s", pthread_self(),
               strerror(errno));
        return -3;
      }

    tot_size += cont;
    if (max_size > L0 && tot_size > max_size) {
      logmsg(LOG_WARNING, "(%lx) chunk content too large", pthread_self);
      return -4;
    }

    if (cont > L0) {
      if (copy_bin(cl, be, cont, res_bytes, no_write)) {
        if (errno)
          logmsg(LOG_NOTICE, "(%lx) error copy chunk cont: %s", pthread_self(),
                 strerror(errno));
        return -4;
      }
    } else
      break;
    /* final CRLF */
    if ((res = get_line(cl, buf, MAXBUF, &line_len)) < 0) {
      logmsg(LOG_NOTICE, "(%lx) error after chunk: %s", pthread_self(),
             strerror(errno));
      return -5;
    } else if (res > 0) {
      logmsg(LOG_NOTICE, "(%lx) unexpected EOF after chunk", pthread_self());
      return -5;
    }
    if (buf[0])
      logmsg(LOG_NOTICE, "(%lx) unexpected after chunk \"%s\"", pthread_self(),
             buf);
    if (!no_write)
      if (BIO_printf(be, "%s\r\n", buf) <= 0) {
        logmsg(LOG_NOTICE, "(%lx) error after chunk write: %s", pthread_self(),
               strerror(errno));
        return -6;
      }
  }
  /* possibly trailing headers */
  for (;;) {
    if ((res = get_line(cl, buf, MAXBUF, &line_len)) < 0) {
      logmsg(LOG_NOTICE, "(%lx) error post-chunk: %s", pthread_self(),
             strerror(errno));
      return -7;
    } else if (res > 0)
      break;
    if (!no_write)
      if (BIO_printf(be, "%s\r\n", buf) <= 0) {
        logmsg(LOG_NOTICE, "(%lx) error post-chunk write: %s", pthread_self(),
               strerror(errno));
        return -8;
      }
    if (!buf[0])
      break;
  }
  if (!no_write)
    if (BIO_flush(be) != 1) {
      logmsg(LOG_NOTICE, "(%lx) copy_chunks flush error: %s", pthread_self(),
             strerror(errno));
      return -4;
    }
  return 0;
}

static int err_to = -1;

typedef struct {
  int timeout;
  RENEG_STATE *reneg_state;
} BIO_ARG;

/*
 * Time-out for client read/gets
 * the SSL manual says not to do it, but it works well enough anyway...
 */
static long
bio_callback(BIO * const bio, const int cmd, const char *argp, int argi,
             long argl, long ret)
{
  BIO_ARG *bio_arg;
  struct pollfd p;
  int to, p_res, p_err;

  if (cmd != BIO_CB_READ && cmd != BIO_CB_WRITE)
    return ret;

  /* a time-out already occured */
  if ((bio_arg = (BIO_ARG *) BIO_get_callback_arg(bio)) == NULL)
    return ret;
  if ((to = bio_arg->timeout * 1000) < 0) {
    errno = ETIMEDOUT;
    return -1;
  }

  /* Renegotiations */
  /* logmsg(LOG_NOTICE, "RENEG STATE %d", bio_arg->reneg_state==NULL?-1:*bio_arg->reneg_state); */
  if (bio_arg->reneg_state != NULL && *bio_arg->reneg_state == RENEG_ABORT) {
    logmsg(LOG_NOTICE, "REJECTING renegotiated session");
    errno = ECONNABORTED;
    return -1;
  }

  if (to == 0)
    return ret;

  for (;;) {
    memset(&p, 0, sizeof(p));
    BIO_get_fd(bio, &p.fd);
    p.events = (cmd == BIO_CB_READ) ? (POLLIN | POLLPRI) : POLLOUT;
    p_res = poll(&p, 1, to);
    p_err = errno;
    switch (p_res) {
      case 1:
        if (cmd == BIO_CB_READ) {
          if ((p.revents & POLLIN) || (p.revents & POLLPRI))
            /* there is readable data */
            return ret;
          else {
#ifdef  EBUG
            logmsg(LOG_WARNING, "(%lx) CALLBACK read 0x%04x poll: %s",
                   pthread_self(), p.revents, strerror(p_err));
#endif
            errno = EIO;
          }
        } else {
          if (p.revents & POLLOUT)
            /* data can be written */
            return ret;
          else {
#ifdef  EBUG
            logmsg(LOG_WARNING, "(%lx) CALLBACK write 0x%04x poll: %s",
                   pthread_self(), p.revents, strerror(p_err));
#endif
            errno = ECONNRESET;
          }
        }
        return -1;
      case 0:
        /* timeout - mark the BIO as unusable for the future */
        bio_arg->timeout = err_to;
#ifdef  EBUG
        logmsg(LOG_WARNING, "(%lx) CALLBACK timeout poll after %d secs: %s",
               pthread_self(), to / 1000, strerror(p_err));
#endif
        errno = ETIMEDOUT;
        return 0;
      default:
        /* error */
        if (p_err != EINTR) {
#ifdef  EBUG
          logmsg(LOG_WARNING, "(%lx) CALLBACK bad %d poll: %s",
                 pthread_self(), p_res, strerror(p_err));
#endif
          return -2;
#ifdef  EBUG
        } else
          logmsg(LOG_WARNING, "(%lx) CALLBACK interrupted %d poll: %s",
                 pthread_self(), p_res, strerror(p_err));
#else
        }
#endif
    }
  }
}

/*
 * Check if the file underlying a BIO is readable
 */
static int is_readable(BIO * const bio, const int to_wait)
{
  struct pollfd p;

  if (BIO_pending(bio) > 0)
    return 1;
  memset(&p, 0, sizeof(p));
  BIO_get_fd(bio, &p.fd);
  p.events = POLLIN | POLLPRI;
  return (poll(&p, 1, to_wait * 1000) > 0);
}

static void free_headers(char **headers)
{
  int i;

  for (i = 0; i < MAXHEADERS; i++)
    if (headers[i])
      free(headers[i]);
  free(headers);
  return;
}

static char **get_headers(BIO * const in, BIO * const cl, const LISTENER * lstn)
{
  char **headers, buf[MAXBUF];
  int res, n, has_eol, line_len;

  /* HTTP/1.1 allows leading CRLF */
  memset(buf, 0, MAXBUF);
  while ((res = BIO_gets(in, buf, MAXBUF - 1)) > 0) {
    has_eol = strip_eol(buf);
    if (buf[0])
      break;
  }

  if (res <= 0) {
    /* this is expected to occur only on client reads */
    /* logmsg(LOG_NOTICE, "headers: bad starting read"); */
    return NULL;
  } else if (!has_eol) {
    /* check for request length limit */
    logmsg(LOG_WARNING, "(%lx) e414 headers: request URI too long",
           pthread_self());
    err_reply(cl, h414, lstn->err414);
    return NULL;
  }
  if ((headers = (char **) calloc(MAXHEADERS, sizeof(char *))) == NULL) {
    logmsg(LOG_WARNING, "(%lx) e500 headers: out of memory", pthread_self());
    err_reply(cl, h500, lstn->err500);
    return NULL;
  }
  if ((headers[0] = (char *) calloc(res + 2, sizeof(char))) == NULL) {
    free_headers(headers);
    logmsg(LOG_WARNING, "(%lx) e500 header: out of memory", pthread_self());
    err_reply(cl, h500, lstn->err500);
    return NULL;
  }
//  memset(headers[0], 0, MAXBUF);
  strncpy(headers[0], buf, res);

  for (n = 1; n < MAXHEADERS; n++) {
    if (get_line(in, buf, MAXBUF, &line_len)) {
      free_headers(headers);
      logmsg(LOG_WARNING, "(%lx) e500 can't read header", pthread_self());
      err_reply(cl, h500, lstn->err500);
      return NULL;
    }
    if (!buf[0])
      return headers;
    if ((headers[n] = (char *) calloc(line_len + 2, sizeof(char))) == NULL) {
      free_headers(headers);
      logmsg(LOG_WARNING, "(%lx) e500 header: out of memory", pthread_self());
      err_reply(cl, h500, lstn->err500);
      return NULL;
    }
//        memset(headers[n], 0, MAXBUF);
    strncpy(headers[n], buf, line_len);
  }

  free_headers(headers);
  logmsg(LOG_NOTICE, "(%lx) e500 too many headers", pthread_self());
  err_reply(cl, h500, lstn->err500);
  return NULL;
}

#define LOG_TIME_SIZE   32
/*
 * Apache log-file-style time format
 */
static void log_time(char *res)
{
  time_t now;
  struct tm *t_now, t_res;

  now = time(NULL);
#ifdef  HAVE_LOCALTIME_R
  t_now = localtime_r(&now, &t_res);
#else
  t_now = localtime(&now);
#endif
  strftime(res, LOG_TIME_SIZE - 1, "%d/%b/%Y:%H:%M:%S %z", t_now);
  return;
}

static double cur_time(void)
{
#ifdef  HAVE_GETTIMEOFDAY
  struct timeval tv;
  struct timezone tz;
  int sv_errno;

  sv_errno = errno;
  gettimeofday(&tv, &tz);
  errno = sv_errno;
  return tv.tv_sec * 1000000.0 + tv.tv_usec;
#else
  return time(NULL) * 1000000.0;
#endif
}

#define LOG_BYTES_SIZE  32
/*
 * Apache log-file-style number format
 */
static void log_bytes(char *res, const LONG cnt)
{
  if (cnt > L0)
#ifdef  HAVE_LONG_LONG_INT
    snprintf(res, LOG_BYTES_SIZE - 1, "%lld", cnt);
#else
    snprintf(res, LOG_BYTES_SIZE - 1, "%ld", cnt);
#endif
  else
    strcpy(res, "-");
  return;
}


/* Cleanup code. This should really be in the pthread_cleanup_push, except for bugs in some implementations */
// if(count_backend->connections > 0)
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
#define clear_error()
#elif OPENSSL_VERSION_NUMBER >= 0x10000000L
#define clear_error() \
    if(ssl != NULL) { ERR_clear_error(); ERR_remove_thread_state(NULL); }
#else
#define clear_error() \
    if(ssl != NULL) { ERR_clear_error(); ERR_remove_state(0); }
#endif

#define clean_all() {   \
    if(flagCount) {decrease_backend_conn(cur_backend); } \
    if(ssl != NULL) { BIO_ssl_shutdown(cl); } \
    if(be != NULL) { BIO_flush(be); BIO_reset(be); BIO_free_all(be); be = NULL; } \
    if(cl != NULL) { BIO_flush(cl); BIO_reset(cl); BIO_free_all(cl); cl = NULL; } \
    if(x509 != NULL) { X509_free(x509); x509 = NULL; } \
    waf_del_transaction(&modsec_transaction); \
    if(waf_rules != NULL) { waf_memo_decrease(waf_rules); waf_memo_clean(waf_rules); } \
    if(body_buff != NULL) {free(body_buff); body_buff = NULL; } \
    clear_error(); \
}

void increase_backend_conn(BACKEND * backend)
{
  int ret_val;

  if (ret_val = pthread_mutex_lock(&backend->mut))
    logmsg(LOG_WARNING, "increase_backend_conn() lock: %s", strerror(ret_val));
  backend->connections++;
  if (ret_val = pthread_mutex_unlock(&backend->mut))
    logmsg(LOG_WARNING, "increase_backend_conn() unlock: %s",
           strerror(ret_val));
}

void decrease_backend_conn(BACKEND * backend)
{
  int ret_val;

  if (ret_val = pthread_mutex_lock(&backend->mut))
    logmsg(LOG_WARNING, "increase_backend_conn() lock: %s", strerror(ret_val));
  backend->connections--;
  if (ret_val = pthread_mutex_unlock(&backend->mut))
    logmsg(LOG_WARNING, "increase_backend_conn() unlock: %s",
           strerror(ret_val));
}


static int zcu_str_find_str(int *off_start, int *off_end, const char *ori_str,
		     int ori_len, const char *match_str, int match_len)
{
	int i, flag = 0;
	*off_start = -1;
	*off_end = -1;

	for (i = 0; i < ori_len && flag < match_len; i++) {
		if (ori_str[i] == match_str[flag]) {
			if (flag == 0)
				*off_start = i;
			flag++;
		} else
			flag = 0;
	}
	if (flag == 0)
		return 0;

	*off_end = *off_start + match_len;
	return 1;
}


static int zcu_str_replace_str(char *buf, const char *ori_str, int ori_len,
			const char *match_str, int match_len, char *replace_str,
			int replace_len)
{
	int offst = -1, offend = -1, offcopy = 0,
	    buf_len = ori_len - match_len + replace_len;

	if (!zcu_str_find_str(&offst, &offend, ori_str, ori_len, match_str,
			      match_len)) {
		return 0;
	}

	if (buf_len > ZCU_DEF_BUFFER_SIZE) {
		logmsg(
			LOG_ERR,
			"String could not be replaced, the buffer size is not enought - %.*s",
			ori_len, ori_str);
		return 0;
	}

	if (offst != 0) {
		memcpy(buf, ori_str, offst);
	}

	offcopy += offst;
	memcpy(buf + offcopy, replace_str, replace_len);

	if (offend != ori_len) {
		offcopy += replace_len;
		memcpy(buf + offcopy, ori_str + offend, ori_len - offend);
	}
	buf[buf_len] = '\0';

	return 1;
}

char url_orig[MAXBUF] = { 0 };

/*
 * handle an HTTP request
 */
void do_http(thr_arg * arg)
{
  int cl_11, be_11, res, chunked, n, sock, no_cont, skip, conn_closed, force_10,
    sock_proto, is_rpc, exp_cont, read_cl_body, is_ws;
  int headers_num = 0;
#if WAF
  int waf_code = 200;
  WAF_ACTION waf_action = ALLOW;
  WAF_RULESET_MEMO *waf_rules = NULL;   // ruleset used for this transaction
  Transaction *modsec_transaction = NULL;
#endif
  int flagCount = 0;
  LISTENER *lstn;
  SERVICE *svc;
  BACKEND *backend, *old_backend = NULL, *cur_backend;
  struct addrinfo from_host, z_addr;
  struct sockaddr_storage from_host_addr;
  BIO *oldcl, *cl, *be, *bb, *b64;
  X509 *x509;
  char request[MAXBUF], response[MAXBUF], buf[MAXBUF], url[MAXBUF],
    loc_path[MAXBUF], **headers, headers_ok[MAXHEADERS], v_host[MAXBUF],
    referer[MAXBUF], u_agent[MAXBUF], u_name[MAXBUF], caddr[MAXADDRBUFF],
    req_time[LOG_TIME_SIZE], s_res_bytes[LOG_BYTES_SIZE], *mh,
    buf_log_tag[MAXBUF], h_xfwf[MAXBUF];
  char *body_buff = NULL;
  char ip_ori[MAXADDRBUFF], ip_dst[MAXADDRBUFF];
  int port_ori, port_dst;
  SSL *ssl, *be_ssl;
  LONG cont, res_bytes;
  regmatch_t matches[4];
  struct linger l;
  time_t exptime;
  double start_req, end_req;
  RENEG_STATE reneg_state;
  BIO_ARG ba1, ba2;

  reneg_state = RENEG_INIT;
  ba1.reneg_state = &reneg_state;
  ba2.reneg_state = &reneg_state;
  ba1.timeout = 0;
  ba2.timeout = 0;
  from_host = ((thr_arg *) arg)->from_host;
  memcpy(&from_host_addr, from_host.ai_addr, from_host.ai_addrlen);
  from_host.ai_addr = (struct sockaddr *) &from_host_addr;
  lstn = ((thr_arg *) arg)->lstn;
  sock = ((thr_arg *) arg)->sock;
  free(((thr_arg *) arg)->from_host.ai_addr);
  free(arg);

  if (lstn->allow_client_reneg)
    reneg_state = RENEG_ALLOW;

  n = 1;
  setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (void *) &n, sizeof(n));
  l.l_onoff = 1;
  l.l_linger = 10;
  setsockopt(sock, SOL_SOCKET, SO_LINGER, (void *) &l, sizeof(l));
#ifdef  TCP_LINGER2
  n = 5;
  setsockopt(sock, SOL_TCP, TCP_LINGER2, (void *) &n, sizeof(n));
#endif
  n = 1;
  setsockopt(sock, SOL_TCP, TCP_NODELAY, (void *) &n, sizeof(n));

  cl = NULL;
  be = NULL;
  ssl = NULL;
  x509 = NULL;

  if ((cl = BIO_new_socket(sock, 1)) == NULL) {
    logmsg(LOG_WARNING, "(%lx) BIO_new_socket failed", pthread_self());
    shutdown(sock, 2);
    close(sock);
    return;
  }
  ba1.timeout = lstn->to;
  BIO_set_callback_arg(cl, (char *) &ba1);
  BIO_set_callback(cl, bio_callback);

  if (lstn->ctx != NULL) {
    if ((ssl = SSL_new(lstn->ctx->ctx)) == NULL) {
      logmsg(LOG_WARNING, "(%lx) SSL_new: failed", pthread_self());
      BIO_reset(cl);
      BIO_free_all(cl);
      return;
    }
    SSL_set_app_data(ssl, &reneg_state);
    SSL_set_bio(ssl, cl, cl);
    if ((bb = BIO_new(BIO_f_ssl())) == NULL) {
      logmsg(LOG_WARNING, "(%lx) BIO_new(Bio_f_ssl()) failed", pthread_self());
      BIO_reset(cl);
      BIO_free_all(cl);
      return;
    }
    BIO_set_ssl(bb, ssl, BIO_CLOSE);
    BIO_set_ssl_mode(bb, 0);

    oldcl = cl;
    cl = bb;
    if (BIO_do_handshake(cl) <= 0) {
      if ((ERR_GET_REASON(ERR_peek_error()) == SSL_R_HTTP_REQUEST)
          && (ERR_GET_LIB(ERR_peek_error()) == ERR_LIB_SSL)) {
        addr2str(caddr, MAXADDRBUFF - 1, &from_host, 1);
        if (lstn->nossl_redir) {
          logmsg(LOG_NOTICE, "(%lx) errNoSsl from %s redirecting to \"%s\"",
                 pthread_self(), caddr, lstn->nossl_url);
          redirect_reply(oldcl, lstn->nossl_url, lstn->nossl_redir);
        } else {
          logmsg(LOG_NOTICE, "(%lx) errNoSsl from %s sending error",
                 pthread_self(), caddr);
          err_reply(oldcl, h400, lstn->errnossl);
        }
      }
      BIO_reset(cl);
      BIO_free_all(cl);
      return;
    } else {
      if ((x509 = SSL_get_peer_certificate(ssl)) != NULL && lstn->clnt_check < 3
          && SSL_get_verify_result(ssl) != X509_V_OK) {
        addr2str(caddr, MAXADDRBUFF - 1, &from_host, 1);
        logmsg(LOG_NOTICE, "Bad certificate from %s", caddr);
        X509_free(x509);
        BIO_reset(cl);
        BIO_free_all(cl);
        return;
      }
    }
  } else {
    x509 = NULL;
  }
  cur_backend = NULL;

  if ((bb = BIO_new(BIO_f_buffer())) == NULL) {
    logmsg(LOG_WARNING, "(%lx) BIO_new(buffer) failed", pthread_self());
    if (x509 != NULL)
      X509_free(x509);
    BIO_reset(cl);
    BIO_free_all(cl);
    return;
  }
  BIO_set_close(cl, BIO_CLOSE);
  BIO_set_buffer_size(cl, MAXBUF);
  cl = BIO_push(bb, cl);

#if WAF
  pthread_mutex_lock(&waf_rules_memo_mtx);
  if (waf_rules_memo && waf_rules_memo->rules) {
    waf_rules = waf_rules_memo;
    waf_memo_increase(waf_rules);
  }
  pthread_mutex_unlock(&waf_rules_memo_mtx);
#endif

  for (cl_11 = be_11 = 0;;) {
    memset(url_orig, '\0', MAXBUF);
    res_bytes = L0;
    is_rpc = -1;
    is_ws = 0;
    v_host[0] = referer[0] = u_agent[0] = u_name[0] = h_xfwf[0] = '\0';
    conn_closed = 0;
    for (n = 0; n < MAXHEADERS; n++)
      headers_ok[n] = 1;
    if ((headers = get_headers(cl, cl, lstn)) == NULL) {
      if (!cl_11) {
        if (errno) {
          addr2str(caddr, MAXADDRBUFF - 1, &from_host, 1);
          logmsg(LOG_NOTICE, "(%lx) error read from %s: %s", pthread_self(),
                 caddr, strerror(errno));
          /* err_reply(cl, h500, lstn->err500); */
        }
      }
      clean_all();
      return;
    }
    memset(req_time, 0, LOG_TIME_SIZE);
    start_req = cur_time();
    log_time(req_time);

    /* check for correct request */
    strncpy(request, headers[0], MAXBUF);
    if (!regexec(&lstn->verb, request, 3, matches, 0)) {
      no_cont =
        !strncasecmp(request + matches[1].rm_so, "HEAD",
                     matches[1].rm_eo - matches[1].rm_so);
      if (!strncasecmp
          (request + matches[1].rm_so, "RPC_IN_DATA",
           matches[1].rm_eo - matches[1].rm_so))
        is_rpc = 1;
      else
        if (!strncasecmp
            (request + matches[1].rm_so, "RPC_OUT_DATA",
             matches[1].rm_eo - matches[1].rm_so))
        is_rpc = 0;
      else
        if (!strncasecmp
            (request + matches[1].rm_so, "GET",
             matches[1].rm_eo - matches[1].rm_so))
        is_ws |= 0x1;
    } else {
      addr2str(caddr, MAXADDRBUFF - 1, &from_host, 1);
      logmsg(LOG_WARNING, "(%lx) e501 bad request \"%s\" from %s",
             pthread_self(), request, caddr);
      err_reply(cl, h501, lstn->err501);
      free_headers(headers);
      clean_all();
      return;
    }
    cl_11 = (request[strlen(request) - 1] == '1');
    strncpy(url_orig, request + matches[2].rm_so, matches[2].rm_eo - matches[2].rm_so);
    n =
      cpURL(url, request + matches[2].rm_so,
            matches[2].rm_eo - matches[2].rm_so);
    if (n != strlen(url)) {
      /* the URL probably contained a %00 aka NULL - which we don't allow */
      addr2str(caddr, MAXADDRBUFF - 1, &from_host, 1);
      logmsg(LOG_NOTICE, "(%lx) e501 URL \"%s\" (contains NULL) from %s",
             pthread_self(), url, caddr);
      err_reply(cl, h501, lstn->err501);
      free_headers(headers);
      clean_all();
      return;
    }
    if (lstn->has_pat && regexec(&lstn->url_pat, url, 0, NULL, 0)) {
      addr2str(caddr, MAXADDRBUFF - 1, &from_host, 1);
      logmsg(LOG_NOTICE, "(%lx) e501 bad URL \"%s\" from %s", pthread_self(),
             url, caddr);
      err_reply(cl, h501, lstn->err501);
      free_headers(headers);
      clean_all();
      return;
    }

    /* check other headers */
    for (chunked = 0, cont = L_1, n = 1, exp_cont = 0;
         n < MAXHEADERS && headers[n]; n++) {
      /* no overflow - see check_header for details */
      switch (check_header(headers[n], buf)) {
        case HEADER_HOST:
          strcpy(v_host, buf);
          break;
        case HEADER_REFERER:
          strcpy(referer, buf);
          break;
        case HEADER_USER_AGENT:
          strcpy(u_agent, buf);
          break;
        case HEADER_CONNECTION:
          if (!strcasecmp("close", buf))
            conn_closed = 1;
          /* Connection: upgrade */
          else if (!regexec(&CONN_UPGRD, buf, 0, NULL, 0))
            is_ws |= 0x2;
          break;
        case HEADER_UPGRADE:
          if (!strcasecmp("websocket", buf))
            is_ws |= 0x4;
        case HEADER_TRANSFER_ENCODING:
          if (cont >= L0)
            headers_ok[n] = 0;
          else if (!strcasecmp("chunked", buf))
            if (chunked)
              headers_ok[n] = 0;
            else
              chunked = 1;
          break;
        case HEADER_CONTENT_LENGTH:
          if (chunked || cont >= 0L)
            headers_ok[n] = 0;
          else {
            if ((cont = ATOL(buf)) < 0L)
              headers_ok[n] = 0;
            if (is_rpc == 1 && (cont < 0x20000L || cont > 0x80000000L))
              is_rpc = -1;
          }
          break;
        case HEADER_EXPECT:
          // By Zen Load Balancer: Supported "Expect: 100-continue" headers
          if (!strcasecmp("100-continue", buf)) {
            if (ignore_100 == 1) {
              headers_ok[n] = 0;
            } else {
              exp_cont = 1;
            }
          }
          break;
        case HEADER_ILLEGAL:
          if (lstn->log_level > 0) {
            addr2str(caddr, MAXADDRBUFF - 1, &from_host, 1);
            logmsg(LOG_NOTICE, "(%lx) bad header from %s (%s)", pthread_self(),
                   caddr, headers[n]);
          }
          headers_ok[n] = 0;
          break;
        case HEADER_X_FORWARDED_FOR:
          strcpy(h_xfwf, buf);
          headers_ok[n] = 0;
          break;
      }
      if (headers_ok[n] && lstn->head_off) {
        /* maybe header to be removed */
        MATCHER *m;

        for (m = lstn->head_off; m; m = m->next)
          if (!(headers_ok[n] = regexec(&m->pat, headers[n], 0, NULL, 0)))
            break;
      }
      /* get User name */
      if (!regexec(&AUTHORIZATION, headers[n], 2, matches, 0)) {
        int inlen;

        if ((bb = BIO_new(BIO_s_mem())) == NULL) {
          logmsg(LOG_WARNING, "(%lx) Can't alloc BIO_s_mem", pthread_self());
          continue;
        }
        if ((b64 = BIO_new(BIO_f_base64())) == NULL) {
          logmsg(LOG_WARNING, "(%lx) Can't alloc BIO_f_base64", pthread_self());
          BIO_free(bb);
          continue;
        }
        b64 = BIO_push(b64, bb);
        BIO_write(bb, headers[n] + matches[1].rm_so,
                  matches[1].rm_eo - matches[1].rm_so);
        BIO_write(bb, "\n", 1);
        if ((inlen = BIO_read(b64, buf, MAXBUF - 1)) <= 0) {
          logmsg(LOG_WARNING, "(%lx) Can't read BIO_f_base64", pthread_self());
          BIO_free_all(b64);
          continue;
        }
        BIO_free_all(b64);
        if ((mh = strchr(buf, ':')) == NULL) {
          logmsg(LOG_WARNING, "(%lx) Unknown authentication", pthread_self());
          continue;
        }
        *mh = '\0';
        strcpy(u_name, buf);
      }
    }

    // number of headers
    headers_num = n;

    /* possibly limited request size */
    if (lstn->max_req > L0 && cont > L0 && cont > lstn->max_req && is_rpc != 1) {
      addr2str(caddr, MAXADDRBUFF - 1, &from_host, 1);
      logmsg(LOG_NOTICE, "(%lx) e501 request too large (%ld) from %s",
             pthread_self(), cont, caddr);
      err_reply(cl, h501, lstn->err501);
      free_headers(headers);
      clean_all();
      return;
    }

    if (be != NULL) {
      if (is_readable(be, 0)) {
        /* The only way it's readable is if it's at EOF, so close it! */
        BIO_reset(be);
        BIO_free_all(be);
        be = NULL;
      }
    }

    /* check that the requested URL still fits the old back-end (if any) */
    if ((svc = get_service(lstn, url, &headers[1])) == NULL) {
      addr2str(caddr, MAXADDRBUFF - 1, &from_host, 1);
      logmsg(LOG_NOTICE, "(%lx) e503 no service \"%s\" from %s %s",
             pthread_self(), request, caddr, v_host[0] ? v_host : "-");
      err_reply(cl, h503, lstn->err503);
      free_headers(headers);
      clean_all();
      return;
    }

    /* get a backend of the service */
    if ((backend =
         get_backend(svc, &from_host, url, &headers[1],
                     lstn->log_level)) == NULL) {
      addr2str(caddr, MAXADDRBUFF - 1, &from_host, 1);
      logmsg(LOG_NOTICE, "service %s, (%lx) e503 no back-end \"%s\" from %s %s",
             svc->name, pthread_self(), request, caddr,
             v_host[0] ? v_host : "-");
      err_reply(cl, h503, lstn->err503);
      free_headers(headers);
      clean_all();
      return;
    }

    /* get a tag for logs with backend and service */
    get_bk_and_srv_string(buf_log_tag, svc, backend);

    if (be != NULL && backend != cur_backend) {

      BIO_reset(be);
      BIO_free_all(be);
      be = NULL;
    }

    while (be == NULL && backend->be_type == 0) {
      switch (backend->addr.ai_family) {
        case AF_INET:
          sock_proto = PF_INET;
          break;
        case AF_INET6:
          sock_proto = PF_INET6;
          break;
        case AF_UNIX:
          sock_proto = PF_UNIX;
          break;
        default:
          logmsg(LOG_WARNING, "%s (%lx) e503 backend: unknown family %d",
                 buf_log_tag, pthread_self(), backend->addr.ai_family);
          err_reply(cl, h503, lstn->err503);
          free_headers(headers);
          clean_all();
          return;
      }
      if ((sock = socket(sock_proto, SOCK_STREAM, 0)) < 0) {
        str_be(buf, MAXBUF - 1, backend);
        logmsg(LOG_WARNING, "%s (%lx) e503 backend %s socket create: %s",
               buf_log_tag, pthread_self(), buf, strerror(errno));
        err_reply(cl, h503, lstn->err503);
        free_headers(headers);
        clean_all();
        return;
      }
      if (connect_nb(sock, &backend->addr, backend->conn_to, buf_log_tag) < 0) {
        str_be(buf, MAXBUF - 1, backend);
        logmsg(LOG_WARNING, "%s (%lx) backend %s connect: %s", buf_log_tag,
               pthread_self(), buf, strerror(errno));
        shutdown(sock, 2);
        close(sock);
        /*
         * kill the back-end only if no HAport is defined for it
         * otherwise allow the HAport mechanism to do its job
         */
        memset(&z_addr, 0, sizeof(z_addr));
        if (memcmp(&(backend->ha_addr), &(z_addr), sizeof(z_addr)) == 0)
          kill_be(svc, backend, BE_KILL);
        /*
         * ...but make sure we don't get into a loop with the same back-end
         */
        old_backend = backend;
        if ((backend =
             get_backend(svc, &from_host, url, &headers[1],
                         lstn->log_level)) == NULL || backend == old_backend) {
          addr2str(caddr, MAXADDRBUFF - 1, &from_host, 1);
          logmsg(LOG_NOTICE, "%s (%lx) e503 no back-end \"%s\" from %s",
                 buf_log_tag, pthread_self(), request, caddr);
          err_reply(cl, h503, lstn->err503);
          free_headers(headers);
          clean_all();
          return;
        }

        /* update the log tag with backend and service */
        get_bk_and_srv_string(buf_log_tag, svc, backend);

        continue;

      }
      if (sock_proto == PF_INET || sock_proto == PF_INET6) {
        n = 1;
        setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (void *) &n, sizeof(n));
        l.l_onoff = 1;
        l.l_linger = 10;
        setsockopt(sock, SOL_SOCKET, SO_LINGER, (void *) &l, sizeof(l));
#ifdef  TCP_LINGER2
        n = 5;
        setsockopt(sock, SOL_TCP, TCP_LINGER2, (void *) &n, sizeof(n));
#endif
        n = 1;
        setsockopt(sock, SOL_TCP, TCP_NODELAY, (void *) &n, sizeof(n));
      }
      if ((be = BIO_new_socket(sock, 1)) == NULL) {
        logmsg(LOG_WARNING, "%s (%lx) e503 BIO_new_socket server failed",
               buf_log_tag, pthread_self());
        shutdown(sock, 2);
        close(sock);
        err_reply(cl, h503, lstn->err503);
        free_headers(headers);
        clean_all();
        return;
      }
      BIO_set_close(be, BIO_CLOSE);
      if (backend->to > 0) {
        ba2.timeout = backend->to;
        BIO_set_callback_arg(be, (char *) &ba2);
        BIO_set_callback(be, bio_callback);
      }

      if (backend->ctx != NULL) {
        if ((be_ssl = SSL_new(backend->ctx)) == NULL) {
          logmsg(LOG_WARNING, "%s (%lx) be z: failed", buf_log_tag,
                 pthread_self());
          err_reply(cl, h503, lstn->err503);
          free_headers(headers);
          clean_all();
          return;
        }

        if (lstn->ctx != NULL && lstn->ssl_forward_sni_server_name) {
          const char *server_name = NULL;
          if ((server_name =
               SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name)) != NULL) {
            if (!SSL_set_tlsext_host_name(be_ssl, server_name)) {
              logmsg(LOG_WARNING, "(%lx) could not set SNI host name  to %s",
                     pthread_self(), server_name);
              err_reply(cl, h503, lstn->err503);
              free_headers(headers);
              clean_all();
              return;
            }
          }
        }
        SSL_set_bio(be_ssl, be, be);
        if ((bb = BIO_new(BIO_f_ssl())) == NULL) {
          logmsg(LOG_WARNING, "%s (%lx) BIO_new(Bio_f_ssl()) failed",
                 buf_log_tag, pthread_self());
          err_reply(cl, h503, lstn->err503);
          free_headers(headers);
          clean_all();
          return;
        }
        BIO_set_ssl(bb, be_ssl, BIO_CLOSE);
        BIO_set_ssl_mode(bb, 1);
        be = bb;
        if (BIO_do_handshake(be) <= 0) {
          str_be(buf, MAXBUF - 1, backend);
          logmsg(LOG_NOTICE, "BIO_do_handshake with %s failed: %s", buf,
                 ERR_error_string(ERR_get_error(), NULL));
          err_reply(cl, h503, lstn->err503);
          free_headers(headers);
          clean_all();
          return;
        }
      }
      if ((bb = BIO_new(BIO_f_buffer())) == NULL) {
        logmsg(LOG_WARNING, "%s (%lx) e503 BIO_new(buffer) server failed",
               buf_log_tag, pthread_self());
        err_reply(cl, h503, lstn->err503);
        free_headers(headers);
        clean_all();
        return;
      }
      BIO_set_buffer_size(bb, MAXBUF);
      BIO_set_close(bb, BIO_CLOSE);
      be = BIO_push(bb, be);
    }

    // add new connection
    if (!flagCount) {
      increase_backend_conn(backend);
      flagCount = 1;
    } else {
      // a new backend will be assigned
      if (cur_backend != backend) {
        increase_backend_conn(backend);
        decrease_backend_conn(cur_backend);
      }
    }

    /* CONNECION STABLISHED */
    cur_backend = backend;

    /* if we have anything but a BACK_END we close the channel */
    if (be != NULL && cur_backend->be_type) {
      BIO_reset(be);
      BIO_free_all(be);
      be = NULL;
    }
// check WAF
#if WAF
    if (waf_rules) {
      if (modsec_transaction)
        waf_del_transaction(&modsec_transaction);
      waf_create_transaction(&modsec_transaction, waf_api, waf_rules->rules);

      // add conexion info to modsecurity
      addr2IpAndPort(ip_ori, &port_ori, MAXADDRBUFF - 1, &from_host);
      addr2IpAndPort(ip_dst, &port_dst, MAXADDRBUFF - 1, &lstn->addr);
      msc_process_connection(modsec_transaction, ip_ori, port_ori, ip_dst,
                             port_dst);

      waf_add_req_head(modsec_transaction, (const char **) headers, headers_num);

      // logmsg(LOG_DEBUG, "%s (%lx) read REQ_BODY? max_body (%d) > cont (%lld), chunked (%d), is_rpc (%d) ",
      //   buf_log_tag, pthread_self(), body_max_size, cont, chunked, is_rpc);
      if (waf_body_enabled(body_max_size, buf_log_tag, cont, chunked, is_rpc, no_cont)) {
        if (read_body(cl, &body_buff, cont) == -1) {
          logmsg(LOG_NOTICE, "(%lx) error managing HTTP request body",
                 pthread_self());
          free_headers(headers);
          clean_all();
          return;
        }
        msc_append_request_body(modsec_transaction, body_buff, cont);
      }

      msc_process_request_body(modsec_transaction);

      waf_action =
        waf_resolution(modsec_transaction, &waf_code, buf, buf_log_tag);
      if (waf_action != ALLOW) {
        if (waf_action == BLOCK)
          err_reply(cl, h403, "replied forbidden");
        else if (waf_action == REDIRECTION)
          redirect_reply(cl, buf, waf_code);

        // close conn
        logmsg(LOG_INFO, "%s (%lx) WAF denied a request from %s", buf_log_tag,
               pthread_self(), ip_ori);

        free_headers(headers);
        clean_all();
        return;
      }
    }
#endif

    /* send the request */
    if (cur_backend->be_type == 0) {
      for (n = 0; n < MAXHEADERS && headers[n]; n++) {
        if (!headers_ok[n])
          continue;
        /* this is the earliest we can check for Destination - we had no back-end before */
        if (lstn->rewr_dest
            && check_header(headers[n], buf) == HEADER_DESTINATION) {
          if (regexec(&LOCATION, buf, 4, matches, 0)) {
            logmsg(LOG_NOTICE, "%s (%lx) Can't parse Destination %s",
                   buf_log_tag, pthread_self(), buf);
            break;
          }
          str_be(caddr, MAXADDRBUFF - 1, cur_backend);
          strcpy(loc_path, buf + matches[3].rm_so);
          snprintf(buf, MAXBUF, "Destination: http://%s%s", caddr, loc_path);
          free(headers[n]);
          if ((headers[n] = strdup(buf)) == NULL) {
            logmsg(LOG_WARNING,
                   "%s (%lx) rewrite Destination - out of memory: %s",
                   buf_log_tag, pthread_self(), strerror(errno));
            free_headers(headers);
            clean_all();
            return;
          }
        }
        if (BIO_printf(be, "%s\r\n", headers[n]) <= 0) {
          str_be(buf, MAXBUF - 1, cur_backend);
          end_req = cur_time();
          logmsg(LOG_WARNING,
                 "%s (%lx) e500 error write to %s/%s: %s (%.3f sec)",
                 buf_log_tag, pthread_self(), buf, request, strerror(errno),
                 (end_req - start_req) / 1000000.0);
          err_reply(cl, h500, lstn->err500);
          free_headers(headers);
          clean_all();
          return;
        }
      }
      /* add header if required */
      if (lstn->add_head != NULL)
        if (BIO_printf(be, "%s\r\n", lstn->add_head) <= 0) {
          str_be(buf, MAXBUF - 1, cur_backend);
          end_req = cur_time();
          logmsg(LOG_WARNING,
                 "%s (%lx) e500 error write AddHeader to %s: %s (%.3f sec)",
                 buf_log_tag, pthread_self(), buf, strerror(errno),
                 (end_req - start_req) / 1000000.0);
          err_reply(cl, h500, lstn->err500);
          free_headers(headers);
          clean_all();
          return;
        }
    }
    free_headers(headers);

    /* if SSL put additional headers for client certificate */
    if (cur_backend->be_type == 0 && ssl != NULL) {
      const SSL_CIPHER *cipher;

      if ((cipher = SSL_get_current_cipher(ssl)) != NULL) {
        SSL_CIPHER_description(cipher, buf, MAXBUF - 1);
        strip_eol(buf);
        if (BIO_printf(be, "X-SSL-cipher: %s/%s\r\n", SSL_get_version(ssl), buf)
            <= 0) {
          str_be(buf, MAXBUF - 1, cur_backend);
          end_req = cur_time();
          logmsg(LOG_WARNING,
                 "%s (%lx) e500 error write X-SSL-cipher to %s: %s (%.3f sec)",
                 buf_log_tag, pthread_self(), buf, strerror(errno),
                 (end_req - start_req) / 1000000.0);
          err_reply(cl, h500, lstn->err500);
          clean_all();
          return;
        }
      }

      if (lstn->clnt_check > 0 && x509 != NULL
          && (bb = BIO_new(BIO_s_mem())) != NULL) {
        int line_len = 0;
        X509_NAME_print_ex(bb, X509_get_subject_name(x509), 8,
                           XN_FLAG_ONELINE & ~ASN1_STRFLGS_ESC_MSB);
        get_line(bb, buf, MAXBUF, &line_len);
        if (BIO_printf(be, "X-SSL-Subject: %s\r\n", buf) <= 0) {
          str_be(buf, MAXBUF - 1, cur_backend);
          end_req = cur_time();
          logmsg(LOG_WARNING,
                 "%s (%lx) e500 error write X-SSL-Subject to %s: %s (%.3f sec)",
                 buf_log_tag, pthread_self(), buf, strerror(errno),
                 (end_req - start_req) / 1000000.0);
          err_reply(cl, h500, lstn->err500);
          BIO_free_all(bb);
          clean_all();
          return;
        }

        X509_NAME_print_ex(bb, X509_get_issuer_name(x509), 8,
                           XN_FLAG_ONELINE & ~ASN1_STRFLGS_ESC_MSB);
        get_line(bb, buf, MAXBUF, &line_len);
        if (BIO_printf(be, "X-SSL-Issuer: %s\r\n", buf) <= 0) {
          str_be(buf, MAXBUF - 1, cur_backend);
          end_req = cur_time();
          logmsg(LOG_WARNING,
                 "%s (%lx) e500 error write X-SSL-Issuer to %s: %s (%.3f sec)",
                 buf_log_tag, pthread_self(), buf, strerror(errno),
                 (end_req - start_req) / 1000000.0);
          err_reply(cl, h500, lstn->err500);
          BIO_free_all(bb);
          clean_all();
          return;
        }

        ASN1_TIME_print(bb, X509_get_notBefore(x509));
        get_line(bb, buf, MAXBUF, &line_len);
        if (BIO_printf(be, "X-SSL-notBefore: %s\r\n", buf) <= 0) {
          str_be(buf, MAXBUF - 1, cur_backend);
          end_req = cur_time();
          logmsg(LOG_WARNING,
                 "%s (%lx) e500 error write X-SSL-notBefore to %s: %s (%.3f sec)",
                 buf_log_tag, pthread_self(), buf, strerror(errno),
                 (end_req - start_req) / 1000000.0);
          err_reply(cl, h500, lstn->err500);
          BIO_free_all(bb);
          clean_all();
          return;
        }

        ASN1_TIME_print(bb, X509_get_notAfter(x509));
        get_line(bb, buf, MAXBUF, &line_len);
        if (BIO_printf(be, "X-SSL-notAfter: %s\r\n", buf) <= 0) {
          str_be(buf, MAXBUF - 1, cur_backend);
          end_req = cur_time();
          logmsg(LOG_WARNING,
                 "%s (%lx) e500 error write X-SSL-notAfter to %s: %s (%.3f sec)",
                 buf_log_tag, pthread_self(), buf, strerror(errno),
                 (end_req - start_req) / 1000000.0);
          err_reply(cl, h500, lstn->err500);
          BIO_free_all(bb);
          clean_all();
          return;
        }
        if (BIO_printf
            (be, "X-SSL-serial: %ld\r\n",
             ASN1_INTEGER_get(X509_get_serialNumber(x509))) <= 0) {
          str_be(buf, MAXBUF - 1, cur_backend);
          end_req = cur_time();
          logmsg(LOG_WARNING,
                 "%s (%lx) e500 error write X-SSL-serial to %s: %s (%.3f sec)",
                 buf_log_tag, pthread_self(), buf, strerror(errno),
                 (end_req - start_req) / 1000000.0);
          err_reply(cl, h500, lstn->err500);
          BIO_free_all(bb);
          clean_all();
          return;
        }
#ifdef  CERT1L
        PEM_write_bio_X509(bb, x509);
        get_line(bb, buf, MAXBUF);
        if (BIO_printf(be, "X-SSL-certificate: %s", buf) <= 0) {
          str_be(buf, MAXBUF - 1, cur_backend);
          end_req = cur_time();
          logmsg(LOG_WARNING,
                 "%s (%lx) e500 error write X-SSL-certificate to %s: %s (%.3f sec)",
                 buf_log_tag, pthread_self(), buf, strerror(errno),
                 (end_req - start_req) / 1000000.0);
          err_reply(cl, h500, lstn->err500);
          BIO_free_all(bb);
          clean_all();
          return;
        }
        while (get_line(bb, buf, MAXBUF) == 0) {
          if (BIO_printf(be, "%s", buf) <= 0) {
            str_be(buf, MAXBUF - 1, cur_backend);
            end_req = cur_time();
            logmsg(LOG_WARNING,
                   "%s (%lx) e500 error write X-SSL-certificate to %s: %s (%.3f sec)",
                   buf_log_tag, pthread_self(), buf, strerror(errno),
                   (end_req - start_req) / 1000000.0);
            err_reply(cl, h500, lstn->err500);
            BIO_free_all(bb);
            clean_all();
            return;
          }
        }
        if (BIO_printf(be, "\r\n", buf) <= 0) {
          str_be(buf, MAXBUF - 1, cur_backend);
          end_req = cur_time();
          logmsg(LOG_WARNING,
                 "%s (%lx) e500 error write X-SSL-certificate to %s: %s (%.3f sec)",
                 buf_log_tag, pthread_self(), buf, strerror(errno),
                 (end_req - start_req) / 1000000.0);
          err_reply(cl, h500, lstn->err500);
          BIO_free_all(bb);
          clean_all();
          return;
        }
#else
        PEM_write_bio_X509(bb, x509);
        get_line(bb, buf, MAXBUF, &line_len);
        if (BIO_printf(be, "X-SSL-certificate: %s\r\n", buf) <= 0) {
          str_be(buf, MAXBUF - 1, cur_backend);
          end_req = cur_time();
          logmsg(LOG_WARNING,
                 "%s (%lx) e500 error write X-SSL-certificate to %s: %s (%.3f sec)",
                 buf_log_tag, pthread_self(), buf, strerror(errno),
                 (end_req - start_req) / 1000000.0);
          err_reply(cl, h500, lstn->err500);
          BIO_free_all(bb);
          clean_all();
          return;
        }
        while (get_line(bb, buf, MAXBUF, &line_len) == 0) {
          if (BIO_printf(be, "\t%s\r\n", buf) <= 0) {
            str_be(buf, MAXBUF - 1, cur_backend);
            end_req = cur_time();
            logmsg(LOG_WARNING,
                   "%s (%lx) e500 error write X-SSL-certificate to %s: %s (%.3f sec)",
                   buf_log_tag, pthread_self(), buf, strerror(errno),
                   (end_req - start_req) / 1000000.0);
            err_reply(cl, h500, lstn->err500);
            BIO_free_all(bb);
            clean_all();
            return;
          }
        }
#endif
        BIO_free_all(bb);
      }
    }
    /* put additional client IP header */
    if (cur_backend->be_type == 0) {
      addr2str(caddr, MAXADDRBUFF - 1, &from_host, 1);
      if (!h_xfwf[0])
        BIO_printf(be, "X-Forwarded-For: %s\r\n", caddr);
	  else
        BIO_printf(be, "X-Forwarded-For: %s, %s\r\n", h_xfwf, caddr);

      /* final CRLF */
      BIO_puts(be, "\r\n");
    }

    /* headers from client were sent to backend; if there was an 'Expect: 100-continue' we wait for the backend
     * to respond and forward this to the client before handling the body of the request.
     * If server does not reply with 'Continue' we'll close connections and bail out without reading the request.
     * Note that since we have no timeouts, we'll keep waiting for the server reply.
     */

    //headers = NULL;            /* headers will be read if exp_cont seen */
    read_cl_body = 1;           /* will be reset to 0 if exp_cont and '100 Continue' not rx'd, to skip */

    if (exp_cont) {             /* 'Expect: 100-continue' header seen! */
      logmsg(LOG_INFO, "Managing connection Expect 100-continue");

      /* flush to the back-end */
      if (cur_backend->be_type == 0 && BIO_flush(be) != 1) {
        str_be(buf, MAXBUF - 1, cur_backend);
        end_req = cur_time();
        addr2str(caddr, MAXADDRBUFF - 1, &from_host, 1);
        logmsg(LOG_NOTICE,
               "%s (%lx) e500 for %s error flush to %s/%s: %s (%.3f sec)",
               buf_log_tag, pthread_self(), caddr, buf, request,
               strerror(errno), (end_req - start_req) / 1000000.0);
        err_reply(cl, h500, lstn->err500);
        clean_all();
        return;
      }

      if ((headers = get_headers(be, cl, lstn)) == NULL) {
        str_be(buf, MAXBUF - 1, cur_backend);
        end_req = cur_time();
        addr2str(caddr, MAXADDRBUFF - 1, &from_host, 1);
        logmsg(LOG_NOTICE,
               "%s (%lx) e500 for %s response error read headers from %s/%s: %s (%.3f secs)",
               buf_log_tag, pthread_self(), caddr, buf, request,
               strerror(errno), (end_req - start_req) / 1000000.0);
        err_reply(cl, h500, lstn->err500);
        clean_all();
        return;
      }
      strncpy(response, headers[0], MAXBUF);    /* get_headers made sure of termination & length */
      be_11 = (response[7] == '1');     /* just in case this is needed somewhere somehow */
      if (regexec(&RESP_SKIP, response, 0, NULL, 0)) {  /* other reply than '100 Continue' ? */
        logmsg(LOG_NOTICE,
               "%s (%lx) didn't get '100 Continue' but '%s' response from backend",
               buf_log_tag, pthread_self(), response);
        conn_closed = 1;        /* force be connection to close; probably overkill but safe */
        read_cl_body = 0;       /* skip reading client body */
      } else {
        /* send the response to client */
        for (n = 0; n < MAXHEADERS && headers[n]; n++) {
          /* logmsg(LOG_NOTICE, "%s (%lx) sending '%s' to client", buf_log_tag, pthread_self(), headers[n]); */
          if (BIO_printf(cl, "%s\r\n", headers[n]) <= 0) {
            if (errno) {
              addr2str(caddr, MAXADDRBUFF - 1, &from_host, 1);
              logmsg(LOG_NOTICE, "%s (%lx) error write headers to %s: %s",
                     buf_log_tag, pthread_self(), caddr, strerror(errno));
            }
            free_headers(headers);
            clean_all();
            return;
          }
        }
        free_headers(headers);
        headers = NULL;

        /* final CRLF */
        BIO_puts(cl, "\r\n");
        if (BIO_flush(cl) != 1) {
          if (errno) {
            addr2str(caddr, MAXADDRBUFF - 1, &from_host, 1);
            logmsg(LOG_NOTICE, "%s (%lx) error flush headers to %s: %s",
                   buf_log_tag, pthread_self(), caddr, strerror(errno));
          }
          clean_all();
          return;
        }
      }
    }

    if (read_cl_body) {         /* read client body if '100 Continue' rx'd or no 'Expect: 100-continue' seen */

      // if body has been read, it was saved in a buffer
      if (body_buff != NULL) {
        if (BIO_write(be, body_buff, cont) != cont) {
          if (errno)
            logmsg(LOG_NOTICE, "%s (%lx) error write request pending: %s",
                   buf_log_tag, pthread_self(), strerror(errno));
          logmsg(LOG_NOTICE,
                 "%s (%lx) Error sending the request to the backend",
                 buf_log_tag, pthread_self());
          clean_all();
          pthread_exit(NULL);
        }
        free(body_buff);
        body_buff = NULL;
      } else if (cl_11 && chunked) {
        /* had Transfer-encoding: chunked so read/write all the chunks (HTTP/1.1 only) */
        if (copy_chunks(cl, be, NULL, cur_backend->be_type, lstn->max_req)) {
          str_be(buf, MAXBUF - 1, cur_backend);
          end_req = cur_time();
          addr2str(caddr, MAXADDRBUFF - 1, &from_host, 1);
          logmsg(LOG_NOTICE,
                 "%s (%lx) e500 for %s copy_chunks to %s/%s (%.3f sec)",
                 buf_log_tag, pthread_self(), caddr, buf, request,
                 (end_req - start_req) / 1000000.0);
          err_reply(cl, h500, lstn->err500);
          clean_all();
          return;
        }
      } else if (cont > L0 && is_rpc != 1) {
        /* had Content-length, so do raw reads/writes for the length */
        if (copy_bin(cl, be, cont, NULL, cur_backend->be_type)) {
          str_be(buf, MAXBUF - 1, cur_backend);
          end_req = cur_time();
          addr2str(caddr, MAXADDRBUFF - 1, &from_host, 1);
          logmsg(LOG_NOTICE,
                 "%s (%lx) e500 for %s error copy client cont to %s/%s: %s (%.3f sec)",
                 buf_log_tag, pthread_self(), caddr, buf, request,
                 strerror(errno), (end_req - start_req) / 1000000.0);
          err_reply(cl, h500, lstn->err500);
          clean_all();
          return;
        }
      } else if (cont > 0L && is_readable(cl, lstn->to)) {
        char one;
        BIO *cl_unbuf;
        /*
         * special mode for RPC_IN_DATA - content until EOF
         * force HTTP/1.0 - client closes connection when done.
         */
        cl_11 = be_11 = 0;

        /*
         * first read whatever is already in the input buffer
         */
        while (BIO_pending(cl)) {
          if (BIO_read(cl, &one, 1) != 1) {
            logmsg(LOG_NOTICE, "%s (%lx) error read request pending: %s",
                   buf_log_tag, pthread_self(), strerror(errno));
            clean_all();
            pthread_exit(NULL);
          }
          if (++res_bytes > cont) {
            logmsg(LOG_NOTICE,
                   "%s (%lx) error read request pending: max. RPC length exceeded",
                   pthread_self());
            clean_all();
            pthread_exit(NULL);
          }
          if (BIO_write(be, &one, 1) != 1) {
            if (errno)
              logmsg(LOG_NOTICE, "%s (%lx) error write request pending: %s",
                     buf_log_tag, pthread_self(), strerror(errno));
            clean_all();
            pthread_exit(NULL);
          }
        }
        BIO_flush(be);

        /*
         * find the socket BIO in the chain
         */
        if ((cl_unbuf =
             BIO_find_type(cl,
                           lstn->ctx ? BIO_TYPE_SSL : BIO_TYPE_SOCKET)) ==
            NULL) {
          logmsg(LOG_WARNING, "%s (%lx) error get unbuffered: %s", buf_log_tag,
                 pthread_self(), strerror(errno));
          clean_all();
          pthread_exit(NULL);
        }

        /*
         * copy till EOF
         */
        while ((res = BIO_read(cl_unbuf, buf, MAXBUF)) > 0) {
          if ((res_bytes += res) > cont) {
            logmsg(LOG_NOTICE,
                   "%s (%lx) error copy request body: max. RPC length exceeded",
                   pthread_self());
            clean_all();
            pthread_exit(NULL);
          }

          if (BIO_write(be, buf, res) != res) {
            if (errno)
              logmsg(LOG_NOTICE, "%s (%lx) error copy request body: %s",
                     buf_log_tag, pthread_self(), strerror(errno));
            clean_all();
            pthread_exit(NULL);
          } else {
            BIO_flush(be);
          }
        }
      }
    }

    /* flush to the back-end */
    if (cur_backend->be_type == 0 && BIO_flush(be) != 1) {
      str_be(buf, MAXBUF - 1, cur_backend);
      end_req = cur_time();
      addr2str(caddr, MAXADDRBUFF - 1, &from_host, 1);
      logmsg(LOG_NOTICE,
             "%s (%lx) e500 for %s error flush to %s/%s: %s (%.3f sec)",
             buf_log_tag, pthread_self(), caddr, buf, request, strerror(errno),
             (end_req - start_req) / 1000000.0);
      err_reply(cl, h500, lstn->err500);
      clean_all();
      return;
    }

    /*
     * check on no_https_11:
     *  - if 0 ignore
     *  - if 1 and SSL force HTTP/1.0
     *  - if 2 and SSL and MSIE force HTTP/1.0
     */
    switch (lstn->noHTTPS11) {
      case 1:
        force_10 = (ssl != NULL);
        break;
      case 2:
        force_10 = (ssl != NULL && strstr(u_agent, "MSIE") != NULL);
        break;
      default:
        force_10 = 0;
        if (lstn->forcehttp10) {
          MATCHER *m;

          for (m = lstn->forcehttp10; m; m = m->next)
            if (!regexec(&m->pat, u_agent, 0, NULL, 0)) {
              force_10 = 1;
              break;
            }
        }
        break;
    }

    /* if we have a redirector */
    if (cur_backend->be_type) {
      memset(buf, 0, sizeof(buf));
      if (!cur_backend->redir_req) {
		if (strstr(cur_backend->url, "${VHOST}")) {
			zcu_str_replace_str(
			  buf, cur_backend->url, strlen(cur_backend->url), "${VHOST}", 8,
			  v_host, strlen(v_host));
		} else
			strncpy(buf, cur_backend->url, sizeof(buf) - 1);
      } else if (cur_backend->redir_req == 1) {
		if (strstr(cur_backend->url, "${VHOST}")) {
			zcu_str_replace_str(
			  buf, cur_backend->url, strlen(cur_backend->url), "${VHOST}", 8,
			  v_host, strlen(v_host));
			strcat(buf, url_orig);
		} else
			snprintf(buf, sizeof(buf) - 1, "%s%s", cur_backend->url, url_orig);
      } else {
        regmatch_t umtch[10];
        char *chptr, *enptr, *srcptr;

        // Redirect Dynamic
        //fprintf(stderr, "redir dynamic url %s replace %s\n", url, cur_backend->url);

        if (regexec(&svc->url->pat, url, 10, umtch, 0))
          logmsg(LOG_WARNING,
                 "URL pattern didn't match in redirdynamic... shouldn't happen %s",
                 url);
        chptr = buf;
        enptr = buf + sizeof(buf) - 1;
        *enptr = '\0';
        srcptr = cur_backend->url;
        for (; *srcptr && chptr < enptr - 1;) {
          if (srcptr[0] == '$' && srcptr[1] == '$') {
            *chptr++ = *srcptr++;
            srcptr++;
          }
          if (srcptr[0] == '$' && isdigit(srcptr[1])) {
            if (chptr + umtch[srcptr[1] - 0x30].rm_eo -
                umtch[srcptr[1] - 0x30].rm_so > enptr - 1)
              break;
            memcpy(chptr, url + umtch[srcptr[1] - 0x30].rm_so,
                   umtch[srcptr[1] - 0x30].rm_eo - umtch[srcptr[1] -
                                                         0x30].rm_so);
            chptr +=
              umtch[srcptr[1] - 0x30].rm_eo - umtch[srcptr[1] - 0x30].rm_so;
            srcptr += 2;
            continue;
          }
          *chptr++ = *srcptr++;
        }
        *chptr++ = '\0';
      }
      redirect_reply(cl, buf, cur_backend->be_type);
      addr2str(caddr, MAXADDRBUFF - 1, &from_host, 1);
      switch (lstn->log_level) {
        case 0:
          break;
        case 1:
        case 2:
          logmsg(LOG_INFO, "%s %s - REDIRECT %s", caddr, request, buf);
          break;
        case 3:
          if (v_host[0])
            logmsg(LOG_INFO, "%s %s - %s [%s] \"%s\" %d 0 \"%s\" \"%s\"",
                   v_host, caddr, u_name[0] ? u_name : "-", req_time, request,
                   cur_backend->be_type, referer, u_agent);
          else
            logmsg(LOG_INFO, "%s - %s [%s] \"%s\" %d 0 \"%s\" \"%s\"", caddr,
                   u_name[0] ? u_name : "-", req_time, request,
                   cur_backend->be_type, referer, u_agent);
          break;
        case 4:
        case 5:
          logmsg(LOG_INFO, "%s - %s [%s] \"%s\" %d 0 \"%s\" \"%s\"", caddr,
                 u_name[0] ? u_name : "-", req_time, request,
                 cur_backend->be_type, referer, u_agent);
          break;
        case 6:
          logmsg(LOG_INFO, "%s - %s [%s] \"%s\" %d 0 \"%s\" \"%s\" \"%s\"",
                 caddr, u_name[0] ? u_name : "-", req_time, request,
                 cur_backend->be_type, buf, referer, u_agent);
          break;
      }
      if (!cl_11 || conn_closed || force_10)
        break;
      continue;
    } else if (is_rpc == 1) {
      /* log RPC_IN_DATA */
      end_req = cur_time();
      memset(s_res_bytes, 0, LOG_BYTES_SIZE);
      /* actual request length */
      log_bytes(s_res_bytes, res_bytes);
      addr2str(caddr, MAXADDRBUFF - 1, &from_host, 1);
      str_be(buf, MAXBUF - 1, cur_backend);
      switch (lstn->log_level) {
        case 0:
          break;
        case 1:
          logmsg(LOG_INFO, "%s %s - -", caddr, request);
          break;
        case 2:
          if (v_host[0])
            logmsg(LOG_INFO, "%s %s - - (%s/%s -> %s) %.3f sec",
                   caddr, request, v_host, svc->name[0] ? svc->name : "-", buf,
                   (end_req - start_req) / 1000000.0);
          else
            logmsg(LOG_INFO, "%s %s - - (%s -> %s) %.3f sec",
                   caddr, request, svc->name[0] ? svc->name : "-", buf,
                   (end_req - start_req) / 1000000.0);
          break;
        case 3:
          logmsg(LOG_INFO, "%s %s - %s [%s] \"%s\" 000 %s \"%s\" \"%s\"",
                 v_host[0] ? v_host : "-",
                 caddr, u_name[0] ? u_name : "-", req_time, request,
                 s_res_bytes, referer, u_agent);
          break;
        case 4:
          logmsg(LOG_INFO, "%s - %s [%s] \"%s\" 000 %s \"%s\" \"%s\"",
                 caddr, u_name[0] ? u_name : "-", req_time, request,
                 s_res_bytes, referer, u_agent);
          break;
        case 5:
          logmsg(LOG_INFO,
                 "%s %s - %s [%s] \"%s\" 000 %s \"%s\" \"%s\" (%s -> %s) %.3f sec",
                 v_host[0] ? v_host : "-", caddr, u_name[0] ? u_name : "-",
                 req_time, request, s_res_bytes, referer, u_agent,
                 svc->name[0] ? svc->name : "-", buf,
                 (end_req - start_req) / 1000000.0);
          break;
      }
      /* no response expected - bail out */
      break;
    }

    /* we'll arrive directly here if '100 Continue' was expected but not received; headers will be valid then */
    /* get the response */
    for (skip = 1; skip;) {
      if ((headers = get_headers(be, cl, lstn)) == NULL) {
        str_be(buf, MAXBUF - 1, cur_backend);
        end_req = cur_time();
        addr2str(caddr, MAXADDRBUFF - 1, &from_host, 1);
        logmsg(LOG_NOTICE,
               "%s (%lx) e500 for %s response error read from %s/%s: %s (%.3f secs)",
               buf_log_tag, pthread_self(), caddr, buf, request,
               strerror(errno), (end_req - start_req) / 1000000.0);
        err_reply(cl, h500, lstn->err500);
        clean_all();
        return;
      }

      strncpy(response, headers[0], MAXBUF);
      be_11 = (response[7] == '1');
      /* responses with code 100 are never passed back to the client */
      if (exp_cont == 1) {
        skip = 0;               /* was: !regexec(&RESP_SKIP, response, 0, NULL, 0); to ignore 100_continue */
        /* some response codes (1xx, 204, 304) have no content */
      } else {
        skip = !regexec(&RESP_SKIP, response, 0, NULL, 0);
      }
      if (!no_cont && !regexec(&RESP_IGN, response, 0, NULL, 0))
        no_cont = 1;
      if (!strncasecmp("101", response + 9, 3))
        is_ws |= 0x10;

      for (n = 0; n < MAXHEADERS; n++)
        headers_ok[n] = 1;
      for (chunked = 0, cont = -1L, n = 1; n < MAXHEADERS && headers[n]; n++) {
        switch (check_header(headers[n], buf)) {
          case HEADER_CONNECTION:
            if (!strcasecmp("close", buf))
              conn_closed = 1;
            /* Connection: upgrade */
            else if (!regexec(&CONN_UPGRD, buf, 0, NULL, 0))
              is_ws |= 0x20;
            break;
          case HEADER_UPGRADE:
            if (!strcasecmp("websocket", buf))
              is_ws |= 0x40;
          case HEADER_TRANSFER_ENCODING:
            if (!strcasecmp("chunked", buf)) {
              chunked = 1;
              no_cont = 0;
            }
            break;
          case HEADER_CONTENT_LENGTH:
            cont = ATOL(buf);
            /* treat RPC_OUT_DATA like reply without content-length */
            if (is_rpc == 0) {
              if (cont >= 0x20000L && cont <= 0x80000000L)
                cont = -1L;
              else
                is_rpc = -1;
            }
            break;
          case HEADER_LOCATION:
            if (v_host[0]
                && need_rewrite(lstn->rewr_loc, buf, loc_path, v_host, lstn,
                                cur_backend)) {
              snprintf(buf, MAXBUF, "Location: %s://%s/%s",
                       (ssl == NULL ? "http" : "https"), v_host, loc_path);
              free(headers[n]);
              if ((headers[n] = strdup(buf)) == NULL) {
                logmsg(LOG_WARNING,
                       "%s (%lx) rewrite Location - out of memory: %s",
                       buf_log_tag, pthread_self(), strerror(errno));
                free_headers(headers);
                clean_all();
                return;
              }
            }
            break;
          case HEADER_CONTLOCATION:
            if (v_host[0]
                && need_rewrite(lstn->rewr_loc, buf, loc_path, v_host, lstn,
                                cur_backend)) {
              snprintf(buf, MAXBUF, "Content-location: %s://%s/%s",
                       (ssl == NULL ? "http" : "https"), v_host, loc_path);
              free(headers[n]);
              if ((headers[n] = strdup(buf)) == NULL) {
                logmsg(LOG_WARNING,
                       "%s (%lx) rewrite Content-location - out of memory: %s",
                       buf_log_tag, pthread_self(), strerror(errno));
                free_headers(headers);
                clean_all();
                return;
              }
            }
            break;
          case HEADER_STRICT_TRANSPORT_SECURITY:
            /* enforce pound's STS header */
            if (svc->sts >= 0)
              headers_ok[n] = 0;
            break;
        }

        /* maybe header to be removed */
        if (headers_ok[n] && lstn->head_off_resp) {
          MATCHER *m;
          for (m = lstn->head_off_resp; m; m = m->next)
            if (!(headers_ok[n] = regexec(&m->pat, headers[n], 0, NULL, 0)))
              break;
        }
      }

      /* possibly record session information (only for cookies/header) */
      upd_session(svc, &headers[1], cur_backend);

      headers_num = n;

#if WAF
      //waf response
      if (waf_rules) {

        waf_add_resp_head(modsec_transaction, (const char **) headers, headers_num);

        //  logmsg(LOG_DEBUG, "%s (%lx) read RESPONSE_BODY? max_body (%d) > cont (%lld), chunked (%d), is_rpc (%d) ",
        //    buf_log_tag, pthread_self(), body_max_size, cont, chunked, is_rpc);

        if (waf_body_enabled(body_max_size, buf_log_tag, cont, chunked, is_rpc, no_cont)) {
          if (read_body(be, &body_buff, cont) == -1) {
            logmsg(LOG_NOTICE, "(%lx) error managing HTTP response body",
                   pthread_self());
            free_headers(headers);
            clean_all();
            return;
          }
          msc_append_response_body(modsec_transaction, body_buff, cont);
        }

        msc_process_response_body(modsec_transaction);

        waf_action =
          waf_resolution(modsec_transaction, &waf_code, buf, buf_log_tag);

        if (waf_action != ALLOW) {
          // Reply error
          if (waf_action == BLOCK)
            err_reply(cl, h403, "replied forbidden");

          else if (waf_action == REDIRECTION)
            redirect_reply(cl, buf, waf_code);

          // close conn
          logmsg(LOG_INFO, "%s (%lx) replied by WAF", buf_log_tag,
                 pthread_self());

          free_headers(headers);
          clean_all();
          return;
        }
      }
      waf_del_transaction(&modsec_transaction);
#endif

      /* send the response */
      if (!skip)
        for (n = 0; n < MAXHEADERS && headers[n]; n++) {
          if (!headers_ok[n])
            continue;
          if (BIO_printf(cl, "%s\r\n", headers[n]) <= 0) {
            if (errno) {
              addr2str(caddr, MAXADDRBUFF - 1, &from_host, 1);
              logmsg(LOG_NOTICE, "%s (%lx) error write to %s: %s", buf_log_tag,
                     pthread_self(), caddr, strerror(errno));
            }
            free_headers(headers);
            clean_all();
            return;
          }
        }
      free_headers(headers);
      if (!skip && ssl && svc->sts >= 0)
        BIO_printf(cl, "Strict-Transport-Security: max-age=%d\r\n", svc->sts);

      if (!skip && cur_backend->be_type == 0 && svc->becookie
          && cur_backend->bekey) {
        char *cp = buf;
        char *ep = buf + sizeof(buf) - 1;
        buf[0] = '\0';
        snprintf(cp, (ep - cp - 1), "Set-Cookie: %s=%s", svc->becookie,
                 cur_backend->bekey);
        cp += strlen(cp);
        if (svc->becage != 0) {
          strncat(cp, "; expires=", ep - cp - 1);
          cp += strlen(cp);
          exptime = time(NULL);
          /* Explicit age?  Or match session timer? (-1) */
          if (svc->becage > 0)
            exptime += svc->becage;
          else
            exptime += svc->sess_ttl;
          strftime(cp, ep - cp - 1, "%a, %e-%b-%Y %H:%M:%S GMT",
                   gmtime(&exptime));
          cp += strlen(cp);
        }
        if (svc->becpath) {
          strncat(cp, "; path=", ep - cp - 1);
          cp += strlen(cp);
          strncat(cp, svc->becpath, ep - cp - 1);
          cp += strlen(cp);
        }
        if (svc->becdomain) {
          strncat(cp, "; domain=", ep - cp - 1);
          cp += strlen(cp);
          strncat(cp, svc->becdomain, ep - cp - 1);
          cp += strlen(cp);
        }
        /*logmsg(LOG_DEBUG, "%s", buf); */
        BIO_printf(cl, "%s\r\n", buf);
      }

      /* add header if required */
      if (lstn->add_head_resp != NULL)
        if (BIO_printf(cl, "%s\r\n", lstn->add_head_resp) <= 0) {
          str_be(buf, MAXBUF - 1, cur_backend);
          end_req = cur_time();
          logmsg(LOG_WARNING,
                 "%s (%lx) e500 error write AddResponseHeader to %s: %s (%.3f sec)",
                 buf_log_tag, pthread_self(), buf, strerror(errno),
                 (end_req - start_req) / 1000000.0);
          err_reply(cl, h500, lstn->err500);
          free_headers(headers);
          clean_all();
          return;
        }

      /* final CRLF */
      if (!skip)
        BIO_puts(cl, "\r\n");
      if (BIO_flush(cl) != 1) {
        if (errno) {
          addr2str(caddr, MAXADDRBUFF - 1, &from_host, 1);
          logmsg(LOG_NOTICE, "%s (%lx) error flush headers to %s: %s",
                 buf_log_tag, pthread_self(), caddr, strerror(errno));
        }
        clean_all();
        return;
      }



      if (!no_cont) {
        // if body has been read, it was saved in a buffer
        if (body_buff != NULL ) {
          if (BIO_write(cl, body_buff, cont) != cont) {
            if (errno)
              logmsg(LOG_NOTICE, "%s (%lx) error write request pending: %s",
                     buf_log_tag, pthread_self(), strerror(errno));
            clean_all();
            logmsg(LOG_NOTICE,
                   "%s (%lx) Error forwarding the body to the client",
                   buf_log_tag, pthread_self());
            pthread_exit(NULL);
          }
          free(body_buff);
          body_buff = NULL;
        } else if (be_11 && chunked) {
          /* ignore this if request was HEAD or similar */
          /* had Transfer-encoding: chunked so read/write all the chunks (HTTP/1.1 only) */
          if (copy_chunks(be, cl, &res_bytes, skip, L0)) {
            /* copy_chunks() has its own error messages */
            clean_all();
            return;
          }
        } else if (cont >= L0) {
          /* may have had Content-length, so do raw reads/writes for the length */
          if (copy_bin(be, cl, cont, &res_bytes, skip)) {
            if (errno)
              logmsg(LOG_NOTICE, "%s (%lx) error copy server cont: %s",
                     buf_log_tag, pthread_self(), strerror(errno));
            clean_all();
            return;
          }
        } else if (!skip) {
          if (is_readable(be, cur_backend->to)) {
            char one;
            BIO *be_unbuf;
            /*
             * old-style response - content until EOF
             * also implies the client may not use HTTP/1.1
             */
            cl_11 = be_11 = 0;

            /*
             * first read whatever is already in the input buffer
             */
            while (BIO_pending(be)) {
              if (BIO_read(be, &one, 1) != 1) {
                logmsg(LOG_NOTICE, "%s (%lx) error read response pending: %s",
                       buf_log_tag, pthread_self(), strerror(errno));
                clean_all();
                return;
              }
              if (BIO_write(cl, &one, 1) != 1) {
                if (errno)
                  logmsg(LOG_NOTICE,
                         "%s (%lx) error write response pending: %s",
                         buf_log_tag, pthread_self(), strerror(errno));
                clean_all();
                return;
              }
              res_bytes++;
            }
            BIO_flush(cl);

            /*
             * find the socket BIO in the chain
             */
            if ((be_unbuf =
                 BIO_find_type(be,
                               cur_backend->ctx ? BIO_TYPE_SSL :
                               BIO_TYPE_SOCKET)) == NULL) {
              logmsg(LOG_WARNING, "%s (%lx) error get unbuffered: %s",
                     buf_log_tag, pthread_self(), strerror(errno));
              clean_all();
              return;
            }

            /*
             * copy till EOF
             */
            while ((res = BIO_read(be_unbuf, buf, MAXBUF)) > 0) {
              if (BIO_write(cl, buf, res) != res) {
                if (errno)
                  logmsg(LOG_NOTICE, "%s (%lx) error copy response body: %s",
                         buf_log_tag, pthread_self(), strerror(errno));
                clean_all();
                return;
              } else {
                res_bytes += res;
                BIO_flush(cl);
              }
            }
          }
        }
        if (BIO_flush(cl) != 1) {
          /* client closes RPC_OUT_DATA connection - no error */
          if (is_rpc == 0 && res_bytes > 0L)
            break;
          if (errno) {
            addr2str(caddr, MAXADDRBUFF - 1, &from_host, 1);
            logmsg(LOG_NOTICE, "%s (%lx) error final flush to %s: %s",
                   buf_log_tag, pthread_self(), caddr, strerror(errno));
          }
          clean_all();
          return;
        }
      } else if (is_ws == 0x77) {
        /*
         * special mode for Websockets - content until EOF
         */
        char one;
        BIO *cl_unbuf;
        BIO *be_unbuf;
        struct pollfd p[2];

        cl_11 = be_11 = 0;

        memset(p, 0, sizeof(p));
        BIO_get_fd(cl, &p[0].fd);
        p[0].events = POLLIN | POLLPRI;
        BIO_get_fd(be, &p[1].fd);
        p[1].events = POLLIN | POLLPRI;

        while (BIO_pending(cl) || BIO_pending(be)
               || poll(p, 2, cur_backend->ws_to * 1000) > 0) {

          /*
           * first read whatever is already in the input buffer
           */
          while (BIO_pending(cl)) {
            if (BIO_read(cl, &one, 1) != 1) {
              logmsg(LOG_NOTICE, "(%lx) error read ws request pending: %s",
                     pthread_self(), strerror(errno));
              clean_all();
              return;
            }
            if (BIO_write(be, &one, 1) != 1) {
              if (errno)
                logmsg(LOG_NOTICE, "(%lx) error write ws request pending: %s",
                       pthread_self(), strerror(errno));
              clean_all();
              return;
            }
          }
          BIO_flush(be);

          while (BIO_pending(be)) {
            if (BIO_read(be, &one, 1) != 1) {
              logmsg(LOG_NOTICE, "(%lx) error read ws response pending: %s",
                     pthread_self(), strerror(errno));
              clean_all();
              return;
            }
            if (BIO_write(cl, &one, 1) != 1) {
              if (errno)
                logmsg(LOG_NOTICE, "(%lx) error write ws response pending: %s",
                       pthread_self(), strerror(errno));
              clean_all();
              return;
            }
            res_bytes++;
          }
          BIO_flush(cl);
          /*
           * find the socket BIO in the chain
           */
          if ((cl_unbuf =
               BIO_find_type(cl,
                             lstn->ctx ? BIO_TYPE_SSL : BIO_TYPE_SOCKET)) ==
              NULL) {
            logmsg(LOG_WARNING, "(%lx) error get unbuffered: %s",
                   pthread_self(), strerror(errno));
            clean_all();
            return;
          }
          if ((be_unbuf =
               BIO_find_type(be,
                             cur_backend->ctx ? BIO_TYPE_SSL : BIO_TYPE_SOCKET))
              == NULL) {
            logmsg(LOG_WARNING, "(%lx) error get unbuffered: %s",
                   pthread_self(), strerror(errno));
            clean_all();
            return;
          }

          /*
           * copy till EOF
           */
          if (p[0].revents) {
            res = BIO_read(cl_unbuf, buf, MAXBUF);
            if (res <= 0) {
              break;
            }
            if (BIO_write(be, buf, res) != res) {
              if (errno)
                logmsg(LOG_NOTICE, "(%lx) error copy ws request body: %s",
                       pthread_self(), strerror(errno));
              clean_all();
              return;
            } else {
              BIO_flush(be);
            }
            p[0].revents = 0;
          }
          if (p[1].revents) {
            res = BIO_read(be_unbuf, buf, MAXBUF);
            if (res <= 0) {
              break;
            }
            if (BIO_write(cl, buf, res) != res) {
              if (errno)
                logmsg(LOG_NOTICE, "(%lx) error copy ws response body: %s",
                       pthread_self(), strerror(errno));
              clean_all();
              return;
            } else {
              res_bytes += res;
              BIO_flush(cl);
            }
            p[1].revents = 0;
          }
        }
      }
    }

    end_req = cur_time();
    upd_be(svc, cur_backend, end_req - start_req);

    /* log what happened */
    memset(s_res_bytes, 0, LOG_BYTES_SIZE);
    log_bytes(s_res_bytes, res_bytes);
    addr2str(caddr, MAXADDRBUFF - 1, &from_host, 1);
    if (anonymise) {
      char *last;

      if ((last = strrchr(caddr, '.')) != NULL
          || (last = strrchr(caddr, ':')) != NULL)
        strcpy(++last, "0");
    }
    str_be(buf, MAXBUF - 1, cur_backend);
    switch (lstn->log_level) {
      case 0:
        break;
      case 1:
        logmsg(LOG_INFO, "%s %s - %s", caddr, request, response);
        break;
      case 2:
        if (v_host[0])
          logmsg(LOG_INFO, "%s %s - %s (%s/%s -> %s) %.3f sec",
                 caddr, request, response, v_host,
                 svc->name[0] ? svc->name : "-", buf,
                 (end_req - start_req) / 1000000.0);
        else
          logmsg(LOG_INFO, "%s %s - %s (%s -> %s) %.3f sec",
                 caddr, request, response, svc->name[0] ? svc->name : "-", buf,
                 (end_req - start_req) / 1000000.0);
        break;
      case 3:
        logmsg(LOG_INFO, "%s %s - %s [%s] \"%s\" %c%c%c %s \"%s\" \"%s\"",
               v_host[0] ? v_host : "-",
               caddr, u_name[0] ? u_name : "-", req_time, request, response[9],
               response[10], response[11], s_res_bytes, referer, u_agent);
        break;
      case 4:
        logmsg(LOG_INFO, "%s - %s [%s] \"%s\" %c%c%c %s \"%s\" \"%s\"",
               caddr, u_name[0] ? u_name : "-", req_time, request, response[9],
               response[10], response[11], s_res_bytes, referer, u_agent);
        break;
      case 5:
        logmsg(LOG_INFO,
               "%s %s - %s [%s] \"%s\" %c%c%c %s \"%s\" \"%s\" (%s -> %s) %.3f sec",
               v_host[0] ? v_host : "-", caddr, u_name[0] ? u_name : "-",
               req_time, request, response[9], response[10], response[11],
               s_res_bytes, referer, u_agent, svc->name[0] ? svc->name : "-",
               buf, (end_req - start_req) / 1000000.0);
        break;
    }

    if (!be_11) {
      BIO_reset(be);
      BIO_free_all(be);
      be = NULL;
    }
    /*
     * Stop processing if:
     *  - client is not HTTP/1.1
     *      or
     *  - we had a "Connection: closed" header
     *      or
     *  - this is an SSL connection and we had a NoHTTPS11 directive
     */
    if (!cl_11 || conn_closed || force_10)
      break;
  }

  /*
   * This may help with some versions of IE with a broken channel shutdown
   */
  if (lstn && lstn->ssl_uncln_shutdn && ssl != NULL) {
    MATCHER *m;
    int found = 0;

    for (m = lstn->ssl_uncln_shutdn; m; m = m->next)
      if (!regexec(&m->pat, u_agent, 0, NULL, 0)) {
        found = 1;
        break;
      }

    if (found)
      SSL_set_shutdown(ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
    else
      SSL_set_shutdown(ssl, SSL_RECEIVED_SHUTDOWN);
  } else if (ssl != NULL)
    SSL_set_shutdown(ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);

  clean_all();
  return;
}

void *thr_http_single(void *dummy)
{
  thr_arg *arg;

  arg = (thr_arg *) dummy;
  if (arg == NULL)
    logmsg(LOG_NOTICE, "NULL get_thr_arg");
  else
    do_http(arg);
}

void *thr_http_pool(void *dummy)
{
  thr_arg *arg;

  for (;;) {
    while ((arg = get_thr_arg()) == NULL)
      logmsg(LOG_NOTICE, "NULL get_thr_arg");
    do_http(arg);
  }
}
