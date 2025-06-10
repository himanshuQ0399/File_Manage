#include "server.h"
#include <nlohmann/json.hpp>
#include <iostream>

using json = nlohmann::json;

std::string clean_metadata_id(std::string id) {
    id.erase(std::remove_if(id.begin(), id.end(), [](char c) {
        if (c == '_') return false;
        unsigned char uc = static_cast<unsigned char>(c);
        return !std::isalnum(uc);
    }), id.end());
    return id;
}

void setup_server(Chunker& chunker, httplib::Server& svr) {
    svr.set_payload_max_length(2 * 1024 * 1024 * 1024); // 2GB
    svr.set_read_timeout(600, 0);
    svr.set_write_timeout(600, 0);

    svr.Post("/files", [&chunker](const httplib::Request& req, httplib::Response& res) {
        auto files = req.get_file_values("file");
        if (files.empty()) {
            res.set_content("No files uploaded", "text/plain");
            res.status = 400;
            return;
        }
        std::vector<std::pair<std::string, std::vector<char>>> file_data;
        std::vector<std::string> content_types;
        for (const auto& file : files) {
            std::string cleaned_filename = chunker.clean_filename(file.filename);
            file_data.emplace_back(cleaned_filename, std::vector<char>(file.content.begin(), file.content.end()));
            content_types.push_back(file.content_type);
        }
        std::vector<std::string> metadata_ids;
        if (chunker.upload_multiple_files(file_data, content_types, metadata_ids)) {
            json response = { {"message", "Files uploaded successfully"}, {"metadata_ids", metadata_ids} };
            res.set_content(response.dump(), "application/json");
            res.status = 201;
        } else {
            res.set_content("Failed to upload files", "text/plain");
            res.status = 500;
        }
    });

    svr.Get("/files", [&chunker](const httplib::Request& req, httplib::Response& res) {
        std::string filename = req.get_param_value("filename");
        if (filename.empty()) {
            res.set_content("Missing filename parameter", "text/plain");
            res.status = 400;
            return;
        }
        std::string cleaned_filename = chunker.clean_filename(filename);
        std::string metadata_id = clean_metadata_id(req.get_param_value("id"));
        std::vector<char> content;
        if (chunker.retrieve_file(cleaned_filename, content, metadata_id)) {
            std::string content_type = chunker.get_content_type(cleaned_filename, metadata_id);
            res.set_content(content.data(), content.size(), content_type);
            res.status = 200;
        } else {
            res.set_content("File not found or metadata_id invalid", "text/plain");
            res.status = 404;
        }
    });

    svr.Delete("/files", [&chunker](const httplib::Request& req, httplib::Response& res) {
        std::string filename = req.get_param_value("filename");
        if (filename.empty()) {
            res.set_content("Missing filename parameter", "text/plain");
            res.status = 400;
            return;
        }
        std::string cleaned_filename = chunker.clean_filename(filename);
        std::string metadata_id = clean_metadata_id(req.get_param_value("id"));
        if (chunker.delete_file(cleaned_filename, metadata_id)) {
            res.set_content("File deleted successfully", "text/plain");
            res.status = 200;
        } else {
            res.set_content("Failed to delete file", "text/plain");
            res.status = 404;
        }
    });

    svr.Put("/files", [&chunker](const httplib::Request& req, httplib::Response& res) {
        std::string filename = req.get_param_value("filename");
        if (filename.empty() || !req.has_file("file")) {
            res.set_content("Missing filename or file", "text/plain");
            res.status = 400;
            return;
        }
        auto file = req.get_file_value("file");
        std::string cleaned_filename = chunker.clean_filename(filename);
        std::vector<char> content(file.content.begin(), file.content.end());
        std::string content_type = file.content_type;
        std::string metadata_id = clean_metadata_id(req.get_param_value("id"));
        if (chunker.update_file(cleaned_filename, content, content_type, metadata_id)) {
            res.set_content("File updated successfully", "text/plain");
            res.status = 200;
        } else {
            res.set_content("Failed to update file", "text/plain");
            res.status = 500;
        }
    });
}