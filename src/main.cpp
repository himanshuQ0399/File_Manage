#include "file_manager.h"
#include "server.h"
#include <httplib.h>
#include <iostream>

int main() {
    FileManager fm;
    httplib::Server svr;
    
    setup_server(fm, svr);
    
    std::cout << "Starting server on port 8080..." << std::endl;
    if (!svr.listen("0.0.0.0", 8080)) {
        std::cerr << "Failed to start server" << std::endl;
        return 1;
    }
    
    return 0;
}