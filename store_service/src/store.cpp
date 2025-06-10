#include "store.h"
#include <fstream>
#include <iostream>

using json = nlohmann::json;

Store::Store() : db_(nullptr) {
    if (!fs::create_directories(STORAGE_DIR)) {
        std::cerr << "[Store] STORAGE_DIR exists or failed: " << STORAGE_DIR << "\n";
    }
    if (!fs::create_directories(METADATA_DIR)) {
        std::cerr << "[Store] METADATA_DIR exists or failed: " << METADATA_DIR << "\n";
    }
    initialize_database();
    rebuild_chunk_ref_counts();
}

Store::~Store() {
    if (db_) {
        sqlite3_close(db_);
    }
}

void Store::initialize_database() {
    fs::path db_path = fs::path(METADATA_DIR) / "file_metadata.db";
    int rc = sqlite3_open(db_path.string().c_str(), &db_);
    if (rc != SQLITE_OK) {
        std::cerr << "[Store] Cannot open database: " << sqlite3_errmsg(db_) << "\n";
        throw std::runtime_error("Database initialization failed");
    }

    // Set UTF-8 encoding
    const char* pragma_sql = "PRAGMA encoding = 'UTF-8'";
    char* err_msg = nullptr;
    rc = sqlite3_exec(db_, pragma_sql, nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        std::cerr << "[Store] PRAGMA error: " << err_msg << "\n";
        sqlite3_free(err_msg);
        throw std::runtime_error("Failed to set UTF-8 encoding");
    }

    const char* create_metadata_sql = R"(
        CREATE TABLE IF NOT EXISTS metadata (
            filename TEXT NOT NULL,
            metadata_id TEXT NOT NULL,
            content_type TEXT,
            size INTEGER,
            created_at INTEGER,
            chunks TEXT,
            PRIMARY KEY (filename, metadata_id)
        )
    )";
    const char* create_ref_counts_sql = R"(
        CREATE TABLE IF NOT EXISTS chunk_ref_counts (
            hash TEXT PRIMARY KEY,
            ref_count INTEGER NOT NULL
        )
    )";

    rc = sqlite3_exec(db_, create_metadata_sql, nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        std::cerr << "[Store] SQL error: " << err_msg << "\n";
        sqlite3_free(err_msg);
        throw std::runtime_error("Failed to create metadata table");
    }
    rc = sqlite3_exec(db_, create_ref_counts_sql, nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        std::cerr << "[Store] SQL error: " << err_msg << "\n";
        sqlite3_free(err_msg);
        throw std::runtime_error("Failed to create chunk_ref_counts table");
    }
    std::cerr << "[Store] Database initialized at: " << db_path << "\n";
}

void Store::rebuild_chunk_ref_counts() {
    std::lock_guard<std::mutex> lock(db_mutex_);
    sqlite3_stmt* stmt;
    const char* sql = "SELECT chunks FROM metadata";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "[RebuildRefCounts] SQL error: " << sqlite3_errmsg(db_) << "\n";
        return;
    }

    std::map<std::string, int> ref_counts;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* chunks_json = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        if (chunks_json) {
            try {
                json chunks = json::parse(chunks_json);
                for (const auto& hash : chunks) {
                    ref_counts[hash.get<std::string>()]++;
                }
            } catch (const std::exception& e) {
                std::cerr << "[RebuildRefCounts] JSON parse error: " << e.what() << "\n";
            }
        }
    }
    sqlite3_finalize(stmt);

    sqlite3_exec(db_, "DELETE FROM chunk_ref_counts", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "BEGIN TRANSACTION", nullptr, nullptr, nullptr);
    for (const auto& [hash, count] : ref_counts) {
        sqlite3_stmt* insert_stmt;
        const char* insert_sql = "INSERT INTO chunk_ref_counts (hash, ref_count) VALUES (?, ?)";
        if (sqlite3_prepare_v2(db_, insert_sql, -1, &insert_stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(insert_stmt, 1, hash.c_str(), hash.size(), SQLITE_TRANSIENT);
            sqlite3_bind_int(insert_stmt, 2, count);
            sqlite3_step(insert_stmt);
            sqlite3_finalize(insert_stmt);
        }
    }
    sqlite3_exec(db_, "COMMIT", nullptr, nullptr, nullptr);
    std::cerr << "[Store] Rebuilt chunk reference counts\n";
}

bool Store::save_chunk(const std::string& hash, const std::vector<char>& content) {
    try {
        std::lock_guard<std::mutex> lock(chunk_mutex_);
        fs::path chunk_path = fs::path(STORAGE_DIR) / hash;
        if (fs::exists(chunk_path)) {
            sqlite3_stmt* stmt;
            const char* sql = "SELECT ref_count FROM chunk_ref_counts WHERE hash = ?";
            if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
                std::cerr << "[SaveChunk] SQL error: " << sqlite3_errmsg(db_) << "\n";
                return false;
            }
            sqlite3_bind_text(stmt, 1, hash.c_str(), hash.size(), SQLITE_TRANSIENT);
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                int ref_count = sqlite3_column_int(stmt, 0);
                sqlite3_finalize(stmt);
                const char* update_sql = "UPDATE chunk_ref_counts SET ref_count = ? WHERE hash = ?";
                if (sqlite3_prepare_v2(db_, update_sql, -1, &stmt, nullptr) == SQLITE_OK) {
                    sqlite3_bind_int(stmt, 1, ref_count + 1);
                    sqlite3_bind_text(stmt, 2, hash.c_str(), hash.size(), SQLITE_TRANSIENT);
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                }
            } else {
                sqlite3_finalize(stmt);
            }
            return true;
        }
        std::ofstream ofs(chunk_path, std::ios::binary);
        if (!ofs) {
            std::cerr << "[SaveChunk] Failed to open: " << chunk_path << "\n";
            return false;
        }
        ofs.write(content.data(), content.size());
        sqlite3_stmt* stmt;
        const char* sql = "INSERT OR REPLACE INTO chunk_ref_counts (hash, ref_count) VALUES (?, 1)";
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            std::cerr << "[SaveChunk] SQL error: " << sqlite3_errmsg(db_) << "\n";
            return false;
        }
        sqlite3_bind_text(stmt, 1, hash.c_str(), hash.size(), SQLITE_TRANSIENT);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        return true;
    } catch (const std::exception& e) {
        std::cerr << "[SaveChunk] Error: " << e.what() << "\n";
        return false;
    }
}

bool Store::retrieve_chunk(const std::string& hash, std::vector<char>& content) {
    try {
        fs::path chunk_path = fs::path(STORAGE_DIR) / hash;
        if (!fs::exists(chunk_path)) {
            std::cerr << "[RetrieveChunk] Chunk not found: " << chunk_path << "\n";
            return false;
        }
        std::ifstream ifs(chunk_path, std::ios::binary);
        if (!ifs) {
            std::cerr << "[RetrieveChunk] Failed to open: " << chunk_path << "\n";
            return false;
        }
        content.assign(std::istreambuf_iterator<char>(ifs), {});
        return true;
    } catch (const std::exception& e) {
        std::cerr << "[RetrieveChunk] Error: " << e.what() << "\n";
        return false;
    }
}

bool Store::save_metadata(const json& metadata) {
    try {
        std::lock_guard<std::mutex> lock(db_mutex_);
        sqlite3_stmt* stmt;
        const char* sql = "INSERT INTO metadata (filename, metadata_id, content_type, size, created_at, chunks) VALUES (?, ?, ?, ?, ?, ?)";
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            std::cerr << "[SaveMetadata] SQL error: " << sqlite3_errmsg(db_) << "\n";
            return false;
        }
        std::string filename = metadata["filename"].get<std::string>();
        std::string metadata_id = metadata["metadata_id"].get<std::string>();
        std::string content_type = metadata["content_type"].get<std::string>();
        std::string chunks_json = metadata["chunks"].dump();
        sqlite3_bind_text(stmt, 1, filename.c_str(), filename.size(), SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, metadata_id.c_str(), metadata_id.size(), SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, content_type.c_str(), content_type.size(), SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 4, metadata["size"].get<int64_t>());
        sqlite3_bind_int64(stmt, 5, metadata["created_at"].get<int64_t>());
        sqlite3_bind_text(stmt, 6, chunks_json.c_str(), chunks_json.size(), SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) != SQLITE_DONE) {
            std::cerr << "[SaveMetadata] SQL error: " << sqlite3_errmsg(db_) << "\n";
            sqlite3_finalize(stmt);
            return false;
        }
        sqlite3_finalize(stmt);
        // Removed chunk ref_count increment logic, as it's handled by save_chunk
        return true;
    } catch (const std::exception& e) {
        std::cerr << "[SaveMetadata] Error: " << e.what() << "\n";
        return false;
    }
}

bool Store::retrieve_metadata(const std::string& filename, const std::string& metadata_id, json& metadata) {
    try {
        std::lock_guard<std::mutex> lock(db_mutex_);
        sqlite3_stmt* stmt;
        const char* sql = metadata_id.empty() ?
            "SELECT * FROM metadata WHERE filename = ? ORDER BY created_at DESC LIMIT 1" :
            "SELECT * FROM metadata WHERE filename = ? AND metadata_id = ?";
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
            std::cerr << "[RetrieveMetadata] SQL error: " << sqlite3_errmsg(db_) << "\n";
            return false;
        }
        sqlite3_bind_text(stmt, 1, filename.c_str(), filename.size(), SQLITE_TRANSIENT);
        if (!metadata_id.empty()) {
            sqlite3_bind_text(stmt, 2, metadata_id.c_str(), metadata_id.size(), SQLITE_TRANSIENT);
        }
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            metadata["filename"] = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            metadata["metadata_id"] = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            metadata["content_type"] = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
            metadata["size"] = sqlite3_column_int64(stmt, 3);
            metadata["created_at"] = sqlite3_column_int64(stmt, 4);
            metadata["chunks"] = json::parse(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5)));
            sqlite3_finalize(stmt);
            return true;
        }
        sqlite3_finalize(stmt);
        return false;
    } catch (const std::exception& e) {
        std::cerr << "[RetrieveMetadata] Error: " << e.what() << "\n";
        return false;
    }
}

bool Store::delete_metadata(const std::string& filename, const std::string& metadata_id) {
    try {
        std::lock_guard<std::mutex> lock(db_mutex_);
        sqlite3_stmt* stmt;
        const char* select_sql = metadata_id.empty() ?
            "SELECT chunks FROM metadata WHERE filename = ? ORDER BY created_at DESC LIMIT 1" :
            "SELECT chunks FROM metadata WHERE filename = ? AND metadata_id = ?";
        if (sqlite3_prepare_v2(db_, select_sql, -1, &stmt, nullptr) != SQLITE_OK) {
            std::cerr << "[DeleteMetadata] SQL error: " << sqlite3_errmsg(db_) << "\n";
            return false;
        }
        sqlite3_bind_text(stmt, 1, filename.c_str(), filename.size(), SQLITE_TRANSIENT);
        if (!metadata_id.empty()) {
            sqlite3_bind_text(stmt, 2, metadata_id.c_str(), metadata_id.size(), SQLITE_TRANSIENT);
        }
        json chunks;
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            chunks = json::parse(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0)));
        } else {
            sqlite3_finalize(stmt);
            std::cerr << "[DeleteMetadata] Metadata not found: " << filename << "\n";
            return false;
        }
        sqlite3_finalize(stmt);

        const char* delete_sql = metadata_id.empty() ?
            "DELETE FROM metadata WHERE filename = ? ORDER BY created_at DESC LIMIT 1" :
            "DELETE FROM metadata WHERE filename = ? AND metadata_id = ?";
        if (sqlite3_prepare_v2(db_, delete_sql, -1, &stmt, nullptr) != SQLITE_OK) {
            std::cerr << "[DeleteMetadata] SQL error: " << sqlite3_errmsg(db_) << "\n";
            return false;
        }
        sqlite3_bind_text(stmt, 1, filename.c_str(), filename.size(), SQLITE_TRANSIENT);
        if (!metadata_id.empty()) {
            sqlite3_bind_text(stmt, 2, metadata_id.c_str(), metadata_id.size(), SQLITE_TRANSIENT);
        }
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        for (const auto& hash : chunks) {
            std::string chunk_hash = hash.get<std::string>();
            const char* ref_sql = "SELECT ref_count FROM chunk_ref_counts WHERE hash = ?";
            if (sqlite3_prepare_v2(db_, ref_sql, -1, &stmt, nullptr) == SQLITE_OK) {
                sqlite3_bind_text(stmt, 1, chunk_hash.c_str(), chunk_hash.size(), SQLITE_TRANSIENT);
                if (sqlite3_step(stmt) == SQLITE_ROW) {
                    int ref_count = sqlite3_column_int(stmt, 0);
                    sqlite3_finalize(stmt);
                    if (ref_count <= 1) {
                        fs::path chunk_path = fs::path(STORAGE_DIR) / chunk_hash;
                        if (fs::exists(chunk_path)) fs::remove(chunk_path);
                        const char* delete_ref_sql = "DELETE FROM chunk_ref_counts WHERE hash = ?";
                        if (sqlite3_prepare_v2(db_, delete_ref_sql, -1, &stmt, nullptr) == SQLITE_OK) {
                            sqlite3_bind_text(stmt, 1, chunk_hash.c_str(), chunk_hash.size(), SQLITE_TRANSIENT);
                            sqlite3_step(stmt);
                            sqlite3_finalize(stmt);
                        }
                    } else {
                        const char* update_ref_sql = "UPDATE chunk_ref_counts SET ref_count = ? WHERE hash = ?";
                        if (sqlite3_prepare_v2(db_, update_ref_sql, -1, &stmt, nullptr) == SQLITE_OK) {
                            sqlite3_bind_int(stmt, 1, ref_count - 1);
                            sqlite3_bind_text(stmt, 2, chunk_hash.c_str(), chunk_hash.size(), SQLITE_TRANSIENT);
                            sqlite3_step(stmt);
                            sqlite3_finalize(stmt);
                        }
                    }
                } else {
                    sqlite3_finalize(stmt);
                }
            }
        }
        return true;
    } catch (const std::exception& e) {
        std::cerr << "[DeleteMetadata] Error: " << e.what() << "\n";
        return false;
    }
}