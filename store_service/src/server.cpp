#include "server.h"
#include <nlohmann/json.hpp>
#include <iostream>

using json = nlohmann::json;

void setup_server(Store& store, httplib::Server& svr) {
    svr.set_payload_max_length(2 * 1024 * 1024 * 1024);
    svr.set_read_timeout(600, 0);
    svr.set_write_timeout(600, 0);

    svr.Post("/chunks", [&store](const httplib::Request& req, httplib::Response& res) {
        std::string hash = req.get_param_value("hash");
        if (hash.empty() || !req.has_file("chunk")) {
            res.set_content("Missing hash or chunk", "text/plain");
            res.status = 400;
            return;
        }
        auto chunk = req.get_file_value("chunk");
        std::vector<char> content(chunk.content.begin(), chunk.content.end());
        if (store.save_chunk(hash, content)) {
            res.set_content("Chunk saved", "text/plain");
            res.status = 201;
        } else {
            res.set_content("Failed to save chunk", "text/plain");
            res.status = 500;
        }
    });

    svr.Get("/chunks", [&store](const httplib::Request& req, httplib::Response& res) {
        std::string hash = req.get_param_value("hash");
        if (hash.empty()) {
            res.set_content("Missing hash parameter", "text/plain");
            res.status = 400;
            return;
        }
        std::vector<char> content;
        if (store.retrieve_chunk(hash, content)) {
            res.set_content(content.data(), content.size(), "application/octet-stream");
            res.status = 200;
        } else {
            res.set_content("Chunk not found", "text/plain");
            res.status = 404;
        }
    });

    svr.Post("/metadata", [&store](const httplib::Request& req, httplib::Response& res) {
        try {
            json metadata = json::parse(req.body);
            if (store.save_metadata(metadata)) {
                res.set_content("Metadata saved", "text/plain");
                res.status = 201;
            } else {
                res.set_content("Failed to save metadata", "text/plain");
                res.status = 500;
            }
        } catch (const std::exception& e) {
            res.set_content("Invalid metadata", "text/plain");
            res.status = 400;
        }
    });

    svr.Get("/metadata", [&store](const httplib::Request& req, httplib::Response& res) {
        std::string filename = req.get_param_value("filename");
        std::string metadata_id = req.get_param_value("id");
        json metadata;
        if (store.retrieve_metadata(filename, metadata_id, metadata)) {
            res.set_content(metadata.dump(), "application/json");
            res.status = 200;
        } else {
            res.set_content("Metadata not found", "text/plain");
            res.status = 404;
        }
    });

    svr.Delete("/metadata", [&store](const httplib::Request& req, httplib::Response& res) {
        std::string filename = req.get_param_value("filename");
        std::string metadata_id = req.get_param_value("id");
        if (store.delete_metadata(filename, metadata_id)) {
            res.set_content("Metadata deleted", "text/plain");
            res.status = 200;
        } else {
            res.set_content("Failed to delete metadata", "text/plain");
            res.status = 404;
        }
    });
}