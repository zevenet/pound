#include "pound.h"

void waf_del_transaction(Transaction ** transac)
{
  if (*transac != NULL) {
    msc_transaction_cleanup(*transac);
    *transac = NULL;
  }
}


void waf_create_transaction(Transaction ** t, ModSecurity * ms, Rules * rules)
{
  *t = msc_new_transaction(ms, rules, &logmsg);
}


int waf_check_rule(char *rule_str)
{
  // waf rules is a global variable
  char *err_msg = NULL;
  Rules *rule = NULL;
  int err_rul = 0;

  rule = msc_create_rules_set();
  //msc_rules_add
  msc_rules_add(rule, rule_str, &err_msg);

  if (err_msg) {
    err_rul = 1;
    logmsg(LOG_ERR, "Error loading waf rules, %s", err_msg);
    free(err_msg);
  }

  msc_rules_cleanup(rule);

  return err_rul;
}


int waf_check_set(char *file)
{
  // waf rules is a global variable
  char *err_msg = NULL;
  Rules *rule = NULL;
  int err_rul = 0;

  rule = msc_create_rules_set();
  //msc_rules_add
  msc_rules_add_file(rule, file, &err_msg);

  if (err_msg) {
    err_rul = 1;
    logmsg(LOG_ERR, "Error loading waf rules, %s", err_msg);
    free(err_msg);
  }

  msc_rules_cleanup(rule);

  return err_rul;
}

void waf_memo_del(WAF_RULESET_MEMO * waf_rules)
{
  msc_rules_cleanup(waf_rules->rules);
  pthread_mutex_destroy(&waf_rules->mut);
  free(waf_rules);
  waf_rules = NULL;
}

int waf_memo_create(WAF_RULESET_MEMO ** waf_rules)
{
  // waf rules is a global variable
  char *err = NULL;
  int err_flag = 0;
  Rules *tmp_set = NULL;
  FILE_LIST *it = NULL;

  if (waf_rules_file) {
    tmp_set = msc_create_rules_set();

    for (it = waf_rules_file; it != NULL; it = it->next) {
      //msc_rules_add
      msc_rules_add_file(tmp_set, it->file, &err);

      if (err) {
        err_flag++;
        msc_rules_cleanup(tmp_set);
        tmp_set = NULL;
        logmsg(LOG_ERR, "Error loading waf rules, %s", err);
        free(err);
        break;
      }
    }
  }

  if (!err_flag) {
    // create struct
    *waf_rules = (WAF_RULESET_MEMO *) malloc(sizeof(WAF_RULESET_MEMO));
    if (!*waf_rules) {
      msc_rules_cleanup(tmp_set);
      err_flag = 1;

      logmsg(LOG_ERR, "Error creating the ruleset, the memory is not enough");


    } else {
      (*waf_rules)->rules = tmp_set;
      (*waf_rules)->counter = 0;
      pthread_mutex_init(&(*waf_rules)->mut, NULL);
    }
  }

  return err_flag;
}


/* It uses the waf memo global struct "waf_rules_memo" */
int waf_reload_rules(void)
{
  // waf rules is a global variable
  int err = 0;
  WAF_RULESET_MEMO *new_waf_ruleset = NULL;
  FILE_LIST *it = NULL;

  err = waf_memo_create(&new_waf_ruleset);

  if (!err) {
    if (err = pthread_mutex_lock(&waf_rules_memo_mtx)) {
      logmsg(LOG_WARNING, "locking waf resource: %s", strerror(err));
      return err;
    }
    // if no one is using waf, delete it
    if (waf_rules_memo && waf_memo_get_counter(waf_rules_memo) == 0)
      waf_memo_del(waf_rules_memo);

    // point memo to the new ruleset
    waf_rules_memo = new_waf_ruleset;

    if (err = pthread_mutex_unlock(&waf_rules_memo_mtx)) {
      logmsg(LOG_WARNING, "unlocking waf resource: %s", strerror(err));
    }
  }
  return err;
}

int waf_memo_lock(WAF_RULESET_MEMO * waf_rules)
{
  int err;
  if (err = pthread_mutex_lock(&waf_rules->mut)) {
    logmsg(LOG_WARNING, "waf_memo_lock(): %s", strerror(err));
  }
  return err;
}

int waf_memo_unlock(WAF_RULESET_MEMO * waf_rules)
{
  int err;
  if (err = pthread_mutex_unlock(&waf_rules->mut)) {
    logmsg(LOG_WARNING, "waf_memo_unlock(): %s", strerror(err));
  }
  return err;
}

/* */
int waf_memo_get_counter(WAF_RULESET_MEMO * waf_rules)
{
  int counter = 0;

  waf_memo_lock(waf_rules);
  counter = (waf_rules->counter);
  waf_memo_unlock(waf_rules);

  return counter;
}

int waf_memo_increase(WAF_RULESET_MEMO * waf_rules)
{
  waf_memo_lock(waf_rules);
  (waf_rules->counter)++;
  waf_memo_unlock(waf_rules);
}

int waf_memo_decrease(WAF_RULESET_MEMO * waf_rules)
{
  waf_memo_lock(waf_rules);
  (waf_rules->counter)--;
  waf_memo_unlock(waf_rules);
}

void waf_memo_clean(WAF_RULESET_MEMO * waf_rules)
{
  // delete struct if it is the last one
  if (waf_memo_get_counter(waf_rules) == 0 && waf_rules != waf_rules_memo)
    waf_memo_del(waf_rules);
}


int
waf_body_enabled(int bodybuf, const char *logtag, LONG body_size, int chunked,
                 int rpc, int no_cont)
{
  int ret = 0;
  if ( no_cont ) {
    // no body is expected (i.e. HEAD verb)
  } else if (!bodybuf) {
    //~ logmsg(LOG_DEBUG, "%s (%lx) WAF skip body, the body is disabled",
    //~ logtag, pthread_self());
  } else if (body_size <= 0) {
    //~ logmsg(LOG_DEBUG, "%s (%lx) WAF skip body, body lenght is unknown",
    //~ logtag, pthread_self());
  } else if (body_size >= INT_MAX) {
    //~ logmsg(LOG_DEBUG, "%s (%lx) WAF skip body, the body is too big",
    //~ logtag, pthread_self());
  } else if (body_size >= bodybuf && bodybuf > 0) {
    //~ logmsg(LOG_DEBUG, "%s (%lx) WAF skip body, body lenght is bigger than body buffer",
    //~ logtag, pthread_self());
  } else if (chunked) {
    //~ logmsg(LOG_DEBUG, "%s (%lx) WAF skip body, body is chunked",
    //~ logtag, pthread_self());
  } else if (rpc == 1) {
    //~ logmsg(LOG_DEBUG, "%s (%lx) WAF skip body, the connection is using RPC protocol",
    //~ logtag, pthread_self());
  } else {
    ret = 1;
  }
  return ret;
}


int
parse_headers(const char *header, char **key, int *key_size, char **value,
              int *value_size)
{
  int fin = 0;
  int parsing_value = 0;
  int i;
  *key = header;
  *key_size = 0;
  *value_size = 0;

  if (header == NULL)
    return -1;

  // look for the separator, ':'
  for (i = 0; i < MAXBUF && !fin; i++) {
    if (!parsing_value) {
      // end key
      if (header[i] == ':')
        fin = 1;
      else if (header[i] == '\0')
        fin = -1;               //wrong parse
    }
  }

  if (fin == 1) {
    i--;
    *key_size = i;
    *value = header + i + 2;
    *value_size = strlen(header) - 2 - *key_size;       // rest size of " :
  }

  return fin;
}


int waf_add_http_info(Transaction * t, const char *header)
{
  int ret = 0;
  int version_str_size = 10;
  char version[10];
  char verb[20];
  char uri[MAXBUF];
  int i = 0;
  int str_ind = 0, version_flag = 0;
  int size = strlen(header);
  int fin;

  // parse verb
  for (fin = 0, str_ind = 0; !fin && i < size; i++, str_ind++) {
    if (header[i] == ' ') {
      verb[str_ind] = '\0';
      fin = 1;
    } else
      verb[str_ind] = header[i];
  }

  // parse path
  for (fin = 0, str_ind = 0; !fin && i < size; i++, str_ind++) {
    if (header[i] == ' ') {
      uri[str_ind] = '\0';
      fin = 1;
    } else
      uri[str_ind] = header[i];
  }

  // parse version
  for (fin = 0, str_ind = 0; !fin && i < size; i++) {
    if (header[i] == '\0' || str_ind == (version_str_size - 1))
      fin = 1;
    else {
      if (version_flag) {
        version[str_ind] = header[i];
        str_ind++;
        // look for after '/': HTTP/<version>
      } else if (!version_flag && header[i] == '/')
        version_flag = 1;
    }
  }
  version[str_ind] = '\0';

  msc_process_uri(t, uri, verb, version);

  return ret;
}


int waf_add_req_head(Transaction * t, char const **headers, int num_headers)
{
  char *key;
  int key_size;
  char *value;
  int value_size;
  int ret = 1;
  int cont = 1;
  int i;

  waf_add_http_info(t, headers[0]);

  // skip first header, it is the VERB, URI and VERSION
  for (i = 1; cont == 1 && i < num_headers; i++) {
    cont = parse_headers(headers[i], &key, &key_size, &value, &value_size);
    if (cont == 1)
      msc_add_n_request_header(t, key, key_size, value, value_size);
    else {
      ret = 0;
    }
  }

  msc_process_request_headers(t);

  return ret;
}


int waf_add_resp_head(Transaction * t, char const **headers, int num_headers)
{
  char *key;
  int key_size;
  char *value;
  int value_size;
  int ret = 1;
  int cont = 1;
  int http_code;
  char http_code_str[4];
  char http_version[9];
  char const *p;

  // parse http response code
  // parse version
  p = headers[0];
  int size = strlen(p);
  int param = 0;
  char aux;
  int i, ic;

  for (i = 0, ic = 0; param < 2 && i < size; i++, ic++) {
    aux = p[i];
    if (aux == ' ')
      aux = '\0';

    if (param == 0)
      http_version[ic] = aux;
    else if (param == 1)
      http_code_str[ic] = aux;

    if (aux == '\0') {
      ic = -1;
      param++;
    }
  }
  http_code = atoi(http_code_str);

  // parse response headers
  for (i = 1; cont == 1 && i < num_headers; i++) {
    cont = parse_headers(headers[i], &key, &key_size, &value, &value_size);
    if (cont == 1) {

      msc_add_n_response_header(t, key, key_size, value, value_size);
    } else {
      ret = 0;
    }
  }

  msc_process_response_headers(t, http_code, http_version);

  return ret;
}


/* it returns -1 on error or another value on success*/
int read_body(BIO * sock, char **buff, int size)
{
  int res=-1;
  int res_bytes = 0;

  if (*buff) {
    logmsg(LOG_NOTICE,
             "(%lx) the body buffer is not clean. Cleaning it",
             pthread_self());
    free (*buff);
    *buff  = NULL;
  }

  *buff = (char *) malloc(size * sizeof(char));

  while ((res = BIO_read(sock, *(buff + res_bytes), size - res_bytes)) > 0) {
    res_bytes += res;

    if (res_bytes > size) {
      logmsg(LOG_NOTICE,
             "(%lx) error reading HTTP body. Body bigger than content-length",
             pthread_self());
      break;
    } else if (res_bytes == size) {
      break;
    }
  }

  return res;
}


int waf_resolution(Transaction * t, int *int_code, char *url, char *tag)
{

  ModSecurityIntervention intervention;
  intervention.status = 200;
  intervention.url = NULL;
  intervention.log = NULL;
  intervention.disruptive = 0;
  WAF_ACTION waf_action = ALLOW;
  int size_copy;

  if (msc_intervention(t, &intervention)) {

    if (!msc_process_logging(t))        // log if any error was found
      logmsg(LOG_WARNING, "%s (%lx) WAF, error processing the log", tag,
             pthread_self());

    if (intervention.url) {
      waf_action = REDIRECTION;
      strcpy(url, intervention.url);
      if (intervention.status == 200)
        intervention.status = 302;      // default value
    } else if (intervention.disruptive) {
      waf_action = BLOCK;
      if (intervention.status == 200)
        intervention.status = 403;      // default value
    }
  }

  if (intervention.log != NULL)
    logmsg(LOG_WARNING, "[WAF,%s] (%lx) %s", tag, pthread_self(),
           intervention.log);

  return waf_action;
}
