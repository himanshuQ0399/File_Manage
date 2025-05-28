#ifndef SERVER_H
#define SERVER_H

#include "file_manager.h"
#include <httplib.h>

void setup_server(FileManager& fm, httplib::Server& svr);

#endif