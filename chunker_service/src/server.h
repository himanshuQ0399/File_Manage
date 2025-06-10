#ifndef SERVER_H
#define SERVER_H
#include "chunker.h"
#include <httplib.h>

void setup_server(Chunker& chunker, httplib::Server& svr);

#endif