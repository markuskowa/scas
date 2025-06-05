// SPDX-FileCopyrightText: 2025 Markus Kowalewski
//
// SPDX-License-Identifier: GPL-3.0-only

#ifndef SCAS_STORE_H
#define SCAS_STORE_H

#include <filesystem>
#include <functional>

#include "hash.h"

namespace fs = std::filesystem;

namespace scas {
  class Store {
    private:
      fs::path dir;

      static const size_t block_size = 64*1024*1024;
      const std::string data_dir_ = "data";
      const std::string gcroot_dir_ = "gc-roots";
      fs::path data_dir;
      fs::path gcroot_dir;

      bool copy_reflink(fs::path source, fs::path target);
      void seal_file(fs::path target);
    public:
      Store(const fs::path& dir);

      enum class reflink: int {
        automatic,
        never,
        always
      };

      fs::path get_dir() const { return dir; }
      void create_store_fs();
      bool store_fs_is_valid();
      bool file_is_in_store(const fs::path& file) const;
      std::string get_hash_from_path(const fs::path& path) const;
      bool path_coincides_with_store(const fs::path& path) const;
      fs::path get_store_path(const std::string& hash);
      fs::path put(const std::string& content, std::string& hash_str);
      fs::path put_stream(std::function<const char*(size_t&)> callback, std::string& hash_str);
      fs::path copy_to_store(const fs::path& path, std::string& hash_str, reflink rl = reflink::automatic);
      fs::path move_to_store(const fs::path& path, std::string& hash, bool add_gc_root = true, reflink rl = reflink::automatic);
      void create_store_link(const fs::path& link, const std::string& hash);
      void register_gc_link(const fs::path& link, const std::string& hash);
      void collect_garbage();
      bool verify_store();

      static Hash::hash_t calc_file_hash(const fs::path& file);
  };

}

#endif /* SCAS_STORE_H */

