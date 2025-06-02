#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "file_manager.h"
#include "server.h"
#include <httplib.h>
#include <iostream>

int main() {
    FileManager fm;
    httplib::SSLServer svr("../server.crt", "../server.key"); // Use SSLServer with certificates

    setup_server(fm, svr);

    std::cout << "Starting HTTPS server on port 443..." << std::endl;
    if (!svr.listen("0.0.0.0", 443)) { // Use port 8443 for testing
        std::cerr << "Failed to start HTTPS server" << std::endl;
        return 1;
    }

    return 0;
}