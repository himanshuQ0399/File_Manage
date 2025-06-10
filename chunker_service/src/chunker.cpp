#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "chunker.h"
#include <openssl/evp.h>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <future>
#include <iostream>

using json = nlohmann::json;

// ThreadPool implementation
ThreadPool::ThreadPool(size_t threads) : stop(false) {
    for (size_t i = 0; i < threads; ++i) {
        workers.emplace_back([this] {
            while (true) {
                std::function<void()> task;
                {
                    std::unique_lock<std::mutex> lock(queue_mutex);
                    condition.wait(lock, [this] { return stop || !tasks.empty(); });
                    if (stop && tasks.empty()) return;
                    task = std::move(tasks.front());
                    tasks.pop();
                }
                task();
            }
        });
    }
}

ThreadPool::~ThreadPool() {
    {
        std::unique_lock<std::mutex> lock(queue_mutex);
        stop = true;
    }
    condition.notify_all();
    for (std::thread& worker : workers) {
        worker.join();
    }
}

void ThreadPool::enqueue(std::function<void()> task) {
    {
        std::unique_lock<std::mutex> lock(queue_mutex);
        if (stop) throw std::runtime_error("Enqueue on stopped ThreadPool");
        tasks.emplace(std::move(task));
    }
    condition.notify_one();
}

Chunker::Chunker(const std::string& store_service_url)
    : store_service_url_(store_service_url), store_client_(store_service_url), thread_pool_(std::thread::hardware_concurrency()) {
    store_client_.enable_server_certificate_verification(false); // Disable for self-signed certs
    std::cerr << "[Chunker] Initialized with store service URL: " << store_service_url_ << "\n";
}

Chunker::~Chunker() {}

std::string Chunker::clean_filename(const std::string& filename) {
    std::string cleaned = filename;
    cleaned.erase(std::remove_if(cleaned.begin(), cleaned.end(), [](char c) {
        return !(std::isalnum(c) || c == '_' || c == '.' || c == '-');
    }), cleaned.end());
    return cleaned.empty() ? "default" : cleaned;
}

std::string Chunker::calculate_sha256(const std::vector<char>& buffer) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create EVP_MD_CTX");
    try {
        if (!EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr)) throw std::runtime_error("EVP_DigestInit_ex failed");
        if (!EVP_DigestUpdate(ctx, buffer.data(), buffer.size())) throw std::runtime_error("EVP_DigestUpdate failed");
        if (!EVP_DigestFinal_ex(ctx, hash, &hash_len)) throw std::runtime_error("EVP_DigestFinal_ex failed");
    } catch (...) {
        EVP_MD_CTX_free(ctx);
        throw;
    }
    EVP_MD_CTX_free(ctx);
    std::stringstream ss;
    for (unsigned int i = 0; i < hash_len; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

std::string Chunker::generate_content_id(const std::vector<std::string>& chunk_hashes) {
    std::string combined;
    for (const auto& hash : chunk_hashes) combined += hash;
    return calculate_sha256(std::vector<char>(combined.begin(), combined.end()));
}

bool Chunker::upload_file(const std::string& filename, const std::vector<char>& content, const std::string& content_type, std::string& out_metadata_id) {
    try {
        std::string cleaned_filename = clean_filename(filename);
        std::cerr << "[Upload] Uploading: " << cleaned_filename << ", size: " << content.size() << "\n";
        json metadata;
        metadata["filename"] = cleaned_filename;
        metadata["size"] = content.size();
        metadata["content_type"] = content_type;
        metadata["created_at"] = std::chrono::system_clock::now().time_since_epoch().count();
        metadata["chunks"] = json::array();
        std::vector<std::string> chunk_hashes;
        size_t offset = 0;
        const size_t MAX_CONCURRENT_TASKS = 4;
        while (offset < content.size()) {
            std::vector<std::future<std::string>> batch_futures;
            size_t start = offset;
            for (size_t i = 0; i < MAX_CONCURRENT_TASKS && offset < content.size(); ++i) {
                size_t bytes_to_read = std::min(CHUNK_SIZE, content.size() - offset);
                std::vector<char> chunk(content.begin() + offset, content.begin() + offset + bytes_to_read);
                batch_futures.push_back(std::async(std::launch::async, [this, chunk]() {
                    return calculate_sha256(chunk);
                }));
                offset += bytes_to_read;
            }
            offset = start;
            for (auto& future : batch_futures) {
                std::string hash = future.get();
                std::vector<char> chunk(content.begin() + offset, content.begin() + offset + std::min(CHUNK_SIZE, content.size() - offset));
                httplib::MultipartFormDataItems items = {
                    {"chunk", std::string(chunk.begin(), chunk.end()), "", "application/octet-stream"}
                };
                // Append hash as query parameter
                std::string url = "/chunks?hash=" + hash;
                auto res = store_client_.Post(url.c_str(), items);
                if (!res || res->status != 201) {
                    std::cerr << "[Upload] Failed to save chunk: " << hash << "\n";
                    return false;
                }
                chunk_hashes.push_back(hash);
                metadata["chunks"].push_back(hash);
                offset += CHUNK_SIZE;
            }
        }
        out_metadata_id = generate_content_id(chunk_hashes);
        metadata["metadata_id"] = out_metadata_id;
        auto res = store_client_.Post("/metadata", metadata.dump(), "application/json");
        if (!res || res->status != 201) {
            std::cerr << "[Upload] Failed to save metadata: " << out_metadata_id << "\n";
            return false;
        }
        std::cerr << "[Upload] Successfully uploaded: " << cleaned_filename << ", metadata_id: " << out_metadata_id << "\n";
        return true;
    } catch (const std::exception& e) {
        std::cerr << "[Upload] Error: " << e.what() << "\n";
        return false;
    }
}

bool Chunker::upload_multiple_files(const std::vector<std::pair<std::string, std::vector<char>>>& files, const std::vector<std::string>& content_types, std::vector<std::string>& out_metadata_ids) {
    try {
        for (size_t i = 0; i < files.size(); ++i) {
            std::string metadata_id;
            if (!upload_file(files[i].first, files[i].second, content_types[i], metadata_id)) {
                std::cerr << "[MultiUpload] Failed to upload: " << files[i].first << "\n";
                return false;
            }
            out_metadata_ids.push_back(metadata_id);
        }
        return true;
    } catch (const std::exception& e) {
        std::cerr << "[MultiUpload] Error: " << e.what() << "\n";
        return false;
    }
}

bool Chunker::retrieve_file(const std::string& filename, std::vector<char>& content, const std::string& metadata_id) {
    try {
        std::string cleaned_filename = clean_filename(filename);
        std::string url = "/metadata?filename=" + cleaned_filename;
        if (!metadata_id.empty()) {
            url += "&id=" + metadata_id;
        }
        auto res = store_client_.Get(url.c_str());
        if (!res || res->status != 200) {
            std::cerr << "[Retrieve] Metadata not found: " << cleaned_filename << "\n";
            return false;
        }
        json metadata = json::parse(res->body);
        content.clear();
        for (const auto& hash : metadata["chunks"]) {
            std::string chunk_hash = hash.get<std::string>();
            auto chunk_res = store_client_.Get(("/chunks?hash=" + chunk_hash).c_str());
            if (!chunk_res || chunk_res->status != 200) {
                std::cerr << "[Retrieve] Failed to retrieve chunk: " << chunk_hash << "\n";
                return false;
            }
            content.insert(content.end(), chunk_res->body.begin(), chunk_res->body.end());
        }
        return true;
    } catch (const std::exception& e) {
        std::cerr << "[Retrieve] Error: " << e.what() << "\n";
        return false;
    }
}

bool Chunker::delete_file(const std::string& filename, const std::string& metadata_id) {
    try {
        std::string cleaned_filename = clean_filename(filename);
        std::string url = "/metadata?filename=" + cleaned_filename;
        if (!metadata_id.empty()) {
            url += "&id=" + metadata_id;
        }
        auto res = store_client_.Delete(url.c_str());
        if (!res || res->status != 200) {
            std::cerr << "[Delete] Failed to delete: " << cleaned_filename << "\n";
            return false;
        }
        return true;
    } catch (const std::exception& e) {
        std::cerr << "[Delete] Error: " << e.what() << "\n";
        return false;
    }
}

bool Chunker::update_file(const std::string& filename, const std::vector<char>& new_content, const std::string& content_type, const std::string& metadata_id) {
    try {
        std::string cleaned_filename = clean_filename(filename);
        std::string target_metadata_id = metadata_id;
        if (target_metadata_id.empty()) {
            std::string url = "/metadata?filename=" + cleaned_filename;
            auto res = store_client_.Get(url.c_str());
            if (!res || res->status != 200) {
                std::cerr << "[Update] Metadata not found: " << cleaned_filename << "\n";
                return false;
            }
            json metadata = json::parse(res->body);
            target_metadata_id = metadata["metadata_id"].get<std::string>();
        }
        std::string new_metadata_id;
        if (!upload_file(cleaned_filename, new_content, content_type, new_metadata_id)) {
            std::cerr << "[Update] Failed to upload new content: " << cleaned_filename << "\n";
            return false;
        }
        if (new_metadata_id != target_metadata_id) {
            std::string url = "/metadata?filename=" + cleaned_filename + "&id=" + target_metadata_id;
            auto res = store_client_.Delete(url.c_str());
            if (!res || res->status != 200) {
                std::cerr << "[Update] Failed to delete old metadata: " << target_metadata_id << "\n";
            }
        }
        return true;
    } catch (const std::exception& e) {
        std::cerr << "[Update] Error: " << e.what() << "\n";
        return false;
    }
}

std::string Chunker::get_content_type(const std::string& filename, const std::string& metadata_id) {
    try {
        std::string cleaned_filename = clean_filename(filename);
        std::string url = "/metadata?filename=" + cleaned_filename;
        if (!metadata_id.empty()) {
            url += "&id=" + metadata_id;
        }
        auto res = store_client_.Get(url.c_str());
        if (!res || res->status != 200) {
            std::cerr << "[ContentType] Metadata not found: " << cleaned_filename << "\n";
            return "application/octet-stream";
        }
        json metadata = json::parse(res->body);
        return metadata.value("content_type", "application/octet-stream");
    } catch (const std::exception& e) {
        std::cerr << "[ContentType] Error: " << e.what() << "\n";
        return "application/octet-stream";
    }
}