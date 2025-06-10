#pragma once
#include <string>
#include <vector>
#include <mutex>
#include <functional>
#include <nlohmann/json.hpp>
#include <httplib.h>
#include<queue>
class ThreadPool {
public:
    ThreadPool(size_t threads);
    ~ThreadPool();
    void enqueue(std::function<void()> task);
private:
    std::vector<std::thread> workers;
    std::queue<std::function<void()>> tasks;
    std::mutex queue_mutex;
    std::condition_variable condition;
    bool stop;
};

class Chunker {
public:
    Chunker(const std::string& store_service_url);
    virtual ~Chunker();
    bool upload_file(const std::string& filename, const std::vector<char>& content, const std::string& content_type, std::string& out_metadata_id);
    bool upload_multiple_files(const std::vector<std::pair<std::string, std::vector<char>>>& files, const std::vector<std::string>& content_types, std::vector<std::string>& out_metadata_ids);
    bool retrieve_file(const std::string& filename, std::vector<char>& content, const std::string& metadata_id = "");
    bool delete_file(const std::string& filename, const std::string& metadata_id = "");
    bool update_file(const std::string& filename, const std::vector<char>& new_content, const std::string& content_type, const std::string& metadata_id = "");
    std::string get_content_type(const std::string& filename, const std::string& metadata_id = "");
    std::string clean_filename(const std::string& filename);
private:
    static constexpr size_t CHUNK_SIZE = 1024 * 1024; // 1MB
    std::string store_service_url_;
    httplib::Client store_client_;
    ThreadPool thread_pool_;
    std::string calculate_sha256(const std::vector<char>& buffer);
    std::string generate_content_id(const std::vector<std::string>& chunk_hashes);
};