#ifndef SVC_H
#define SVC_H

#include "pound.h"
#include "pound_sync_enum.h"

void t_add(SERVICE *const srv, const char *key, const void *content,
           const size_t cont_len, unsigned long timestamp);
void *t_find(SERVICE *const srv, char *const key);
void t_remove(SERVICE *const srv, char *const key);
#endif  // SVC_H
