#ifndef POUND_SYNC_ENUM_H
#define POUND_SYNC_ENUM_H
typedef enum _action_type {
  CLEAR_DATA = 0,
  SYNC_REQUEST = 1, // Reserved
  SESS_ADD = 2,
  SESS_DELETE = 3,
  SESS_UPDATE = 4,
  SESS_WRITE = 5,
  BCK_ADD = 20,
  BCK_DELETE = 21,
  BCK_UPDATE = 22,

} ACTION_TYPE;
#endif // POUND_SYNC_ENUM_H
