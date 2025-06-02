#pragma once
#include <filesystem>
#include <string>
#include <vector>
#include <mutex>
#include <map>
#include <queue>
#include <thread>
#include <condition_variable>
#include <functional>
#include <nlohmann/json.hpp>

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

class FileManager {
public:
    FileManager();
    virtual ~FileManager();
    bool upload_file(const std::string& filename, const std::vector<char>& content, const std::string& content_type, std::string& out_metadata_id);
    bool upload_multiple_files(const std::vector<std::pair<std::string, std::vector<char>>>& files, const std::vector<std::string>& content_types, std::vector<std::string>& out_metadata_ids);
    bool retrieve_file(const std::string& filename, std::vector<char>& content, const std::string& metadata_id = "");
    bool delete_file(const std::string& filename, const std::string& metadata_id = "");
    bool update_file(const std::string& filename, const std::vector<char>& new_content, const std::string& content_type, const std::string& metadata_id = "");
private:
    void rebuild_chunk_ref_counts();
    static constexpr size_t CHUNK_SIZE = 1024 * 1024; // 1MB
    static const std::string STORAGE_DIR;
    static const std::string METADATA_DIR;
    std::mutex chunk_mutex;
    std::mutex index_mutex;
    std::map<std::string, int> chunk_ref_count;
    ThreadPool thread_pool;

    std::string calculate_sha256(const std::vector<char>& buffer);
    bool save_chunk(const std::string& hash, const std::vector<char>& content);
    bool retrieve_chunk(const std::string& hash, std::vector<char>& content);
    std::string generate_content_id(const std::vector<std::string>& chunk_hashes); // New CID function
    nlohmann::json load_index();
    bool save_index(const nlohmann::json& index);
};