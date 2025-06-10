#pragma once
#include <filesystem>
#include <string>
#include <vector>
#include <mutex>
#include <nlohmann/json.hpp>
#include <sqlite3.h>

namespace fs = std::filesystem;

class Store {
public:
    Store();
    virtual ~Store();
    bool save_chunk(const std::string& hash, const std::vector<char>& content);
    bool retrieve_chunk(const std::string& hash, std::vector<char>& content);
    bool save_metadata(const nlohmann::json& metadata);
    bool retrieve_metadata(const std::string& filename, const std::string& metadata_id, nlohmann::json& metadata);
    bool delete_metadata(const std::string& filename, const std::string& metadata_id);
private:
    static const std::string STORAGE_DIR;
    static const std::string METADATA_DIR;
    sqlite3* db_;
    std::mutex chunk_mutex_;
    std::mutex db_mutex_;
    void initialize_database();
    void rebuild_chunk_ref_counts();
};

inline const std::string Store::STORAGE_DIR = "C:\\Users\\Qikfox\\Documents\\file_parallelism\\build\\release\\chunks";
inline const std::string Store::METADATA_DIR = "C:\\Users\\Qikfox\\Documents\\file_parallelism\\build\\release\\metadata";