#include "pound.h"

void
waf_del_transaction(Transaction **transac) {
  if (*transac != NULL) {
    msc_transaction_cleanup(*transac);
    *transac = NULL;
  }
}


void
waf_create_transaction(Transaction **t, ModSecurity *ms, Rules *rules) {
  *t = msc_new_transaction( ms, rules, &logmsg);
}


int
waf_check_rule(char *rule_str) {
  // waf rules is a global variable
  char *err_msg = NULL;
  Rules *rule = NULL;
  int err_rul = 0;

  rule = msc_create_rules_set();
  //msc_rules_add
  msc_rules_add( rule, rule_str, &err_msg);

  if (err_msg) {
    err_rul = 1;
    logmsg (LOG_ERR,"Error loading waf rules, %s", err_msg);
    free (err_msg);
  }

  msc_rules_cleanup(rule);

  return err_rul;
}


int
waf_check_set(char *file) {
  // waf rules is a global variable
  char *err_msg = NULL;
  Rules *rule = NULL;
  int err_rul = 0;

  rule = msc_create_rules_set();
  //msc_rules_add
  msc_rules_add_file( rule, file, &err_msg);

  if (err_msg) {
    err_rul = 1;
    logmsg(LOG_ERR,"Error loading waf rules, %s", err_msg);
    free (err_msg);
  }

  msc_rules_cleanup(rule);

  return err_rul;
}



int
waf_reload_rules(void) {
  // waf rules is a global variable
  char *err = NULL;
  int err_flag  = 0;
  Rules *tmp_set = NULL;
  FILE_LIST *it = NULL;

  if ( waf_rules_file) {
    tmp_set = msc_create_rules_set();

    for ( it = waf_rules_file; it != NULL; it=it->next ) {
      //msc_rules_add
      msc_rules_add_file( tmp_set, it->file, &err);

      if (err) {
        err_flag++;
        msc_rules_cleanup(tmp_set);
        tmp_set = NULL;
        logmsg(LOG_ERR,"Error loading waf rules, %s", err);
        free (err);
        break;
      }
    }
  }

  if ( !err_flag) {
      if ( waf_rules )
        msc_rules_cleanup(waf_rules);
      // Point to the new set
      waf_rules = tmp_set;
    }

  return err_flag;
}


int
waf_body_enabled(int bodybuf, const char *logtag, int body_size, int chunked, int rpc) {
  int ret=0;
  if (!body_size) {
//    logmsg(LOG_DEBUG, "%s (%lx) WAF skip body, body lenght is unknown",
//          logtag, pthread_self());
  } else if(!bodybuf) {
//    logmsg(LOG_DEBUG, "%s (%lx) WAF skip body, the body is disabled",
//        logtag, pthread_self());
  } else if(body_size >= bodybuf && bodybuf >0) {
//    logmsg(LOG_DEBUG, "%s (%lx) WAF skip body, body lenght is bigger than body buffer",
//        logtag, pthread_self());
  } else if (chunked){
//    logmsg(LOG_DEBUG, "%s (%lx) WAF skip body, body is chunked",
//          logtag, pthread_self());
  } else if (rpc==1){
//    logmsg(LOG_DEBUG, "%s (%lx) WAF skip body, the connection is using RPC protocol",
//          logtag, pthread_self());
  } else {
    ret = 1;
  }
  return ret;
}


int
parse_headers( const char *header, char **key, int *key_size,char **value, int *value_size ) {
  int fin = 0;
  int flag_clr=0;
  int parsing_value=0;
  int i;
  *key = header;
  *key_size = 0;
  *value_size = 0;

  if (header == NULL)
    return -1;

  // look for the separator, ':'
  for ( i=0; i<MAXBUF && !fin; i++ ) {
    if (!parsing_value) {
      // end key
      if (header[i] == ':')
        fin = 1;
      else if (header[i] == '\0')
        fin = -1;  //wrong parse
    }
  }

  if (fin == 1) {
    i--;
    *key_size = i;
    *value=header+i+2;
    *value_size = strlen(header)-2-*key_size; // rest size of " :
  }

  return fin;
}


int
waf_add_http_info(Transaction *t, const char *header) {
  int ret = 0;
  char version[5];
  char verb[20];
  char uri[512];
  int i = 0;
  int str_ind=0;
  int vers_flag= 0;
  int size = strlen(header);
  int fin;

  // parse verb
  for (fin=0,str_ind=0;!fin && i<size; i++, str_ind++) {
    if ( header[i] == ' ' ) {
      verb[str_ind] = '\0';
      fin=1;
    }
    else
      verb[str_ind] = header[i];
  }

  // parse path
  for (fin=0,str_ind=0;!fin && i<size; i++, str_ind++) {
    if ( header[i] == ' ' ) {
      uri[str_ind] = '\0';
      fin=1;
    }
    else
      uri[str_ind] = header[i];
  }

  // parse version
  for (fin=0,str_ind=0;!fin && i<size; i++) {
   if (header[i] == '\0')
     fin=1;

   else {
    if ( vers_flag ) {
     version[str_ind]=header[i];
     str_ind++;
    }
    else if (!vers_flag && header[i] == '/')
      vers_flag=1;
    }
  }

  msc_process_uri(t, uri, verb, version);

  return ret;
}


int
waf_add_req_head(Transaction *t, char const **headers, int num_headers) {
  char *key;
  int key_size;
  char *value;
  int value_size;
  int ret = 1;
  int cont=1;
  int i;

  waf_add_http_info(t, headers[0]);

  // skip first header, it is the VERB, URI and VERSION
  for(i = 1; cont == 1 && i<num_headers; i++) {
     cont = parse_headers( headers[i], &key, &key_size, &value, &value_size);
     if ( cont == 1 )
       msc_add_n_request_header(t, key, key_size, value, value_size);
     else {
       ret = 0;
     }
  }

  msc_process_request_headers(t);

  return ret;
}


int
waf_add_resp_head(Transaction *t, char const **headers, int num_headers) {
  char *key;
  int key_size;
  char *value;
  int value_size;
  int ret = 1;
  int cont=1;
  int http_code;
  char http_code_str[4];
  char http_version[9];
  char const *p;

  // parse http response code
  // parse version
  p=headers[0];
  int size = strlen(p);
  int param=0;
  char aux;
  int i, ic;

  for (i=0, ic=0; param<2 && i<size; i++, ic++) {
    aux=p[i];
    if ( aux == ' ' )
      aux = '\0';

    if (param == 0)
      http_version[ic]=aux;
    else if (param == 1)
      http_code_str[ic]=aux;

    if ( aux == '\0' ) {
      ic=-1;
      param++;
    }
  }
  http_code=atoi(http_code_str);

  // parse response headers
  for(i = 1; cont == 1 && i<num_headers; i++) {
     cont = parse_headers( headers[i], &key, &key_size, &value, &value_size);
     if ( cont == 1 )
       msc_add_n_response_header(t, key, key_size, value, value_size);
     else {
       ret = 0;
     }
  }

  msc_process_response_headers(t, http_code, http_version);

  return ret;
}


int
read_body(BIO *sock, char **buff, int size)
{
  if (*buff)
    logmsg(LOG_ERR, "(%lx) body buffer is busy", pthread_self());
  else {
    *buff=(char *)malloc(size*sizeof(char));
    while(BIO_read(sock, *buff, size) < size){}
  }
}


int
waf_resolution(Transaction *t, int *int_code, char **url, char *tag) {

  ModSecurityIntervention intervention;
  intervention.status = 200;
  intervention.url = NULL;
  intervention.log = NULL;
  intervention.disruptive = 0;
  WAF_ACTION waf_action = ALLOW;

  if (msc_intervention(t,&intervention)) {

    if (!msc_process_logging(t)) // log if any error was found
      logmsg(LOG_WARNING, "%s (%lx) WAF, error processing the log", tag, pthread_self());

    if (intervention.url) {
      waf_action = REDIRECTION;
      if (intervention.status == 200)
        intervention.status = 302;  // default value
    } else if (intervention.disruptive) {
      waf_action = BLOCK;
      if (intervention.status == 200)
        intervention.status = 403;  // default value
    }
  }

  if (intervention.log != NULL)
    logmsg(LOG_WARNING, "[WAF,%s] (%lx) %s", tag, pthread_self(), intervention.log );

  return waf_action;
}
