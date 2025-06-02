#include "file_manager.h"
#include <openssl/evp.h>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <random>
#include <iostream>
#include <future>
namespace fs = std::filesystem;
using json = nlohmann::json;

const std::string FileManager::STORAGE_DIR = "chunks";
const std::string FileManager::METADATA_DIR = "metadata";

// ThreadPool implementation remains unchanged
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

FileManager::FileManager() : thread_pool(std::thread::hardware_concurrency()) {
    fs::create_directories(STORAGE_DIR);
    fs::create_directories(METADATA_DIR);
    rebuild_chunk_ref_counts();
}

FileManager::~FileManager() {}

std::string FileManager::generate_content_id(const std::vector<std::string>& chunk_hashes) {
    // Combine all chunk hashes into a single string
    std::string combined;
    for (const auto& hash : chunk_hashes) {
        combined += hash;
    }
    // Calculate SHA-256 hash of the combined string
    return calculate_sha256(std::vector<char>(combined.begin(), combined.end()));
}

void FileManager::rebuild_chunk_ref_counts() {
    json index = load_index();
    for (const auto& [filename, ids] : index.items()) {
        for (const auto& id : ids) {
            fs::path metadata_path = fs::path(METADATA_DIR) / (filename + "_" + id.get<std::string>() + ".json");
            if (!fs::exists(metadata_path)) continue;
            
            std::ifstream metadata_file(metadata_path);
            if (!metadata_file) continue;
            
            try {
                json metadata = json::parse(metadata_file);
                for (const auto& hash : metadata["chunks"]) {
                    chunk_ref_count[hash.get<std::string>()]++;
                }
            } catch (...) {
                // Ignore invalid metadata files
            }
        }
    }
}

nlohmann::json FileManager::load_index() {
    try {
        std::lock_guard<std::mutex> lock(index_mutex);
        fs::path index_path = fs::path(METADATA_DIR) / "index.json";
        std::ifstream ifs(index_path);
        if (!ifs.is_open()) return json::object();
        
        json combined = json::parse(ifs);
        
        // Restore reference counts
        if (combined.contains("ref_counts")) {
            std::lock_guard<std::mutex> chunk_lock(chunk_mutex);
            for (const auto& [hash, count] : combined["ref_counts"].items()) {
                chunk_ref_count[hash] = count.get<int>();
            }
        }
        
        return combined.contains("files") ? combined["files"] : json::object();
    } catch (const std::exception& e) {
        std::cerr << "[Index] Error: " << e.what() << std::endl;
        return json::object();
    }
}

bool FileManager::save_index(const nlohmann::json& index) {
    try {
        std::lock_guard<std::mutex> lock(index_mutex);
        fs::path index_path = fs::path(METADATA_DIR) / "index.json";
        
        // Create combined index with reference counts
        json combined;
        combined["files"] = index;
        
        // Add reference counts
        json ref_counts;
        {
            std::lock_guard<std::mutex> chunk_lock(chunk_mutex);
            for (const auto& [hash, count] : chunk_ref_count) {
                ref_counts[hash] = count;
            }
        }
        combined["ref_counts"] = ref_counts;
        
        std::ofstream ofs(index_path);
        if (!ofs) return false;
        ofs << combined.dump(2);
        return true;
    } catch (const std::exception& e) {
        std::cerr << "[Index] Error: " << e.what() << std::endl;
        return false;
    }
}

std::string FileManager::calculate_sha256(const std::vector<char>& buffer) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create EVP_MD_CTX");

    try {
        if (!EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) ||
            !EVP_DigestUpdate(ctx, buffer.data(), buffer.size()) ||
            !EVP_DigestFinal_ex(ctx, hash, &hash_len)) {
            throw std::runtime_error("SHA256 computation failed");
        }
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

bool FileManager::save_chunk(const std::string& hash, const std::vector<char>& content) {
    try {
        std::lock_guard<std::mutex> lock(chunk_mutex);
        fs::path chunk_path = fs::path(STORAGE_DIR) / hash;
        
        // If chunk already exists, just increment ref count
        if (fs::exists(chunk_path)) {
            chunk_ref_count[hash]++;
            return true;
        }
        
        // Save new chunk
        std::ofstream ofs(chunk_path, std::ios::binary);
        if (!ofs) return false;
        ofs.write(content.data(), content.size());
        chunk_ref_count[hash] = 1;  // Initialize ref count
        return true;
    } catch (const std::exception& e) {
        std::cerr << "[Save Chunk] Error: " << e.what() << std::endl;
        return false;
    }
}

bool FileManager::upload_file(const std::string& filename, const std::vector<char>& content, const std::string& content_type, std::string& out_metadata_id) {
    try {
        json metadata;
        metadata["filename"] = filename;
        metadata["size"] = content.size();
        metadata["content_type"] = content_type;
        metadata["created_at"] = std::chrono::system_clock::now().time_since_epoch().count();
        metadata["chunks"] = json::array();

        std::vector<std::string> chunk_hashes;
        std::vector<std::future<std::string>> hash_futures;
        size_t offset = 0;

        // Parallel hashing
        while (offset < content.size()) {
            size_t bytes_to_read = std::min(CHUNK_SIZE, content.size() - offset);
            std::vector<char> chunk(content.begin() + offset, content.begin() + offset + bytes_to_read);
            hash_futures.push_back(std::async(std::launch::async, [this, chunk]() {
                return calculate_sha256(chunk);
            }));
            offset += bytes_to_read;
        }

        // Collect hashes in order
        offset = 0;
        for (auto& future : hash_futures) {
            std::string hash = future.get();
            std::vector<char> chunk(content.begin() + offset, content.begin() + offset + std::min(CHUNK_SIZE, content.size() - offset));
            if (!save_chunk(hash, chunk)) return false;
            chunk_hashes.push_back(hash);
            offset += CHUNK_SIZE;
        }

        // Generate CID based on chunk hashes
        std::string metadata_id = generate_content_id(chunk_hashes);
        out_metadata_id = metadata_id;

        // Check if file with same CID already exists
        json index = load_index();
        if (index.contains(filename) && std::find(index[filename].begin(), index[filename].end(), metadata_id) != index[filename].end()) {
            // File already exists, increment ref counts for chunks
            std::lock_guard<std::mutex> lock(chunk_mutex);
            for (const auto& hash : chunk_hashes) {
                chunk_ref_count[hash]++;
            }
            return true; // No need to save metadata again
        }

        metadata["chunks"] = chunk_hashes;
        fs::path metadata_path = fs::path(METADATA_DIR) / (filename + "_" + metadata_id + ".json");
        std::ofstream metadata_file(metadata_path);
        if (!metadata_file) return false;
        metadata_file << metadata.dump(2);

        if (!index.contains(filename)) index[filename] = json::array();
        index[filename].push_back(metadata_id);
        if (!save_index(index)) return false;

        return true;
    } catch (const std::exception& e) {
        std::cerr << "[Upload] Error: " << e.what() << std::endl;
        return false;
    }
}

bool FileManager::upload_multiple_files(const std::vector<std::pair<std::string, std::vector<char>>>& files, const std::vector<std::string>& content_types, std::vector<std::string>& out_metadata_ids) {
    try {
        for (size_t i = 0; i < files.size(); ++i) {
            std::string metadata_id;
            if (!upload_file(files[i].first, files[i].second, content_types[i], metadata_id)) {
                return false;
            }
            out_metadata_ids.push_back(metadata_id);
        }
        return true;
    } catch (const std::exception& e) {
        std::cerr << "[Multi Upload] Error: " << e.what() << std::endl;
        return false;
    }
}

bool FileManager::retrieve_file(const std::string& filename, std::vector<char>& content, const std::string& metadata_id) {
    try {
        std::string target_metadata_id = metadata_id.empty() ? load_index()[filename].back().get<std::string>() : metadata_id;
        fs::path metadata_path = fs::path(METADATA_DIR) / (filename + "_" + target_metadata_id + ".json");
        std::ifstream metadata_file(metadata_path);
        if (!metadata_file.is_open()) return false;

        json metadata = json::parse(metadata_file);
        content.clear();
        for (const auto& hash : metadata["chunks"]) {
            std::vector<char> chunk_content;
            if (!retrieve_chunk(hash.get<std::string>(), chunk_content)) return false;
            content.insert(content.end(), chunk_content.begin(), chunk_content.end());
        }
        return true;
    } catch (const std::exception& e) {
        std::cerr << "[Retrieve] Error: " << e.what() << std::endl;
        return false;
    }
}

bool FileManager::retrieve_chunk(const std::string& hash, std::vector<char>& content) {
    try {
        fs::path chunk_path = fs::path(STORAGE_DIR) / hash;
        if (!fs::exists(chunk_path)) return false;
        std::ifstream chunk_file(chunk_path, std::ios::binary);
        if (!chunk_file) return false;
        content.assign((std::istreambuf_iterator<char>(chunk_file)), {});
        return true;
    } catch (const std::exception& e) {
        std::cerr << "[Retrieve Chunk] Error: " << e.what() << std::endl;
        return false;
    }
}

bool FileManager::delete_file(const std::string& filename, const std::string& metadata_id) {
    try {
        std::string target_metadata_id = metadata_id.empty() ? load_index()[filename].back().get<std::string>() : metadata_id;
        fs::path metadata_path = fs::path(METADATA_DIR) / (filename + "_" + target_metadata_id + ".json");
        json metadata;
        {
            std::ifstream metadata_file(metadata_path);
            if (!metadata_file.is_open()) return false;
            metadata = json::parse(metadata_file);
        }

        {
            std::lock_guard<std::mutex> lock(chunk_mutex);
            for (const auto& hash : metadata["chunks"]) {
                std::string chunk_hash = hash.get<std::string>();
                if (--chunk_ref_count[chunk_hash] == 0) {
                    fs::remove(fs::path(STORAGE_DIR) / chunk_hash);
                    chunk_ref_count.erase(chunk_hash);
                }
            }
        }

        fs::remove(metadata_path);
        json index = load_index();
        if (index.contains(filename)) {
            auto& ids = index[filename];
            ids.erase(std::remove(ids.begin(), ids.end(), target_metadata_id), ids.end());
            if (ids.empty()) index.erase(filename);
            save_index(index);
        }
        return true;
    } catch (const std::exception& e) {
        std::cerr << "[Delete] Error: " << e.what() << std::endl;
        return false;
    }
}

bool FileManager::update_file(const std::string& filename, const std::vector<char>& new_content, const std::string& content_type, const std::string& metadata_id) {
    try {
        std::string target_metadata_id = metadata_id.empty() ? load_index()[filename].back().get<std::string>() : metadata_id;
        fs::path metadata_path = fs::path(METADATA_DIR) / (filename + "_" + target_metadata_id + ".json");
        json old_metadata;
        {
            std::ifstream metadata_file(metadata_path);
            if (!metadata_file.is_open()) return false;
            old_metadata = json::parse(metadata_file);
        }

        json new_metadata;
        new_metadata["filename"] = filename;
        new_metadata["size"] = new_content.size();
        new_metadata["content_type"] = content_type;
        new_metadata["created_at"] = old_metadata["created_at"];
        new_metadata["chunks"] = json::array();

        std::vector<std::string> new_hashes;
        std::vector<std::future<std::string>> hash_futures;
        size_t offset = 0;

        // Parallel hashing
        while (offset < new_content.size()) {
            size_t bytes_to_read = std::min(CHUNK_SIZE, new_content.size() - offset);
            std::vector<char> chunk(new_content.begin() + offset, new_content.begin() + offset + bytes_to_read);
            hash_futures.push_back(std::async(std::launch::async, [this, chunk]() {
                return calculate_sha256(chunk);
            }));
            offset += bytes_to_read;
        }

        // Collect hashes and save chunks
        offset = 0;
        for (auto& future : hash_futures) {
            std::string hash = future.get();
            std::vector<char> chunk(new_content.begin() + offset, new_content.begin() + offset + std::min(CHUNK_SIZE, new_content.size() - offset));
            if (!save_chunk(hash, chunk)) return false;
            new_hashes.push_back(hash);
            offset += CHUNK_SIZE;
        }

        // Generate new CID for updated file
        std::string new_metadata_id = generate_content_id(new_hashes);

        // Remove old metadata file if new CID is different
        if (new_metadata_id != target_metadata_id) {
            fs::remove(metadata_path);
            json index = load_index();
            if (index.contains(filename)) {
                auto& ids = index[filename];
                ids.erase(std::remove(ids.begin(), ids.end(), target_metadata_id), ids.end());
                if (!index[filename].contains(new_metadata_id)) {
                    index[filename].push_back(new_metadata_id);
                }
                save_index(index);
            }
        }

        {
            std::lock_guard<std::mutex> lock(chunk_mutex);
            for (const auto& hash : old_metadata["chunks"].get<std::vector<std::string>>()) {
                if (--chunk_ref_count[hash] == 0) {
                    fs::remove(fs::path(STORAGE_DIR) / hash);
                    chunk_ref_count.erase(hash);
                }
            }
        }

        new_metadata["chunks"] = new_hashes;
        fs::path new_metadata_path = fs::path(METADATA_DIR) / (filename + "_" + new_metadata_id + ".json");
        std::ofstream new_metadata_file(new_metadata_path);
        if (!new_metadata_file) return false;
        new_metadata_file << new_metadata.dump(2);
        return true;
    } catch (const std::exception& e) {
        std::cerr << "[Update] Error: " << e.what() << std::endl;
        return false;
    }
}