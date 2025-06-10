#ifndef SERVER_H
#define SERVER_H
#include "store.h"
#include <httplib.h>

void setup_server(Store& store, httplib::Server& svr);

#endif