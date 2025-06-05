// SPDX-FileCopyrightText: 2025 Markus Kowalewski
//
// SPDX-License-Identifier: GPL-3.0-only

#include <fstream>
#include <iostream>
#include <fcntl.h>    // For open(), ioctl()
#include <unistd.h>   // For close()
#include <sys/ioctl.h> // For ioctl()
#include <linux/ioctl.h>
#include <linux/fs.h>
#include "store.h"

namespace scas {

  Store::Store(const fs::path& dir) :
    dir(dir),
    data_dir(dir / data_dir_),
    gcroot_dir(dir / gcroot_dir_)
  {}

  void Store::seal_file(fs::path target){
    fs::permissions(
      target,
      fs::perms::owner_write | fs::perms::group_write | fs::perms::others_write,
      fs::perm_options::remove
    );
  }

  void Store::create_store_fs() {
    if ( fs::exists(dir) )
      throw std::runtime_error("Directory already exists");

    fs::create_directories(dir);
    fs::create_directory(data_dir);
    fs::create_directory(gcroot_dir);
  }

  bool Store::store_fs_is_valid() {
    if (!fs::is_directory(data_dir))
      return false;

    if (!fs::is_directory(gcroot_dir))
      return false;

    // iterate over file names and check if valid sha256 name
    // check if write persmission are removed

    return true;
  }

  bool Store::path_coincides_with_store(const fs::path& path) const {
    std::string rel = fs::relative(path, data_dir);
    if (rel.length() == 0) return false;
    if (rel[0] == '.') return false;

    return true;
  }

  bool Store::file_is_in_store(const fs::path& file) const {
    if (fs::is_regular_file(data_dir / file))
      return true;

    if (path_coincides_with_store(file) && fs::is_regular_file(data_dir / fs::canonical(file).filename()))
      return true;

    return false;
  }

  std::string Store::get_hash_from_path(const fs::path& path) const {
    auto can_path = fs::canonical(path);

    if ( file_is_in_store(can_path.filename()) )
      return can_path.filename();

    throw std::runtime_error("File not in store");
  }

  fs::path Store::get_store_path(const std::string& hash) {
    return data_dir / hash;
  }

  bool Store::copy_reflink(fs::path source, fs::path target){
    bool success = true;

    auto source_fd = open(source.c_str(), O_RDONLY);
    if (source_fd == -1)
      throw std::invalid_argument("Opening of source file failed");

    auto dest_fd = open(target.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0666);
    if (dest_fd == -1) {
      close(source_fd);
      throw std::invalid_argument("Opening of target file failed");
    }

    if (ioctl(dest_fd, FICLONE, source_fd) == -1) {
      success = false;
    }

    if (dest_fd != -1) close(dest_fd);
    if (source_fd != -1) close(dest_fd);

    return success;
  }

  fs::path Store::copy_to_store(const fs::path& path, std::string& hash_str, reflink rl){
    if (path_coincides_with_store(path))
      throw std::invalid_argument("Source file can not be in store's data directory");

    if (!fs::is_regular_file(path))
      throw std::invalid_argument("Can only copy regular files into store");

    auto hash = calc_file_hash(path);
    hash_str = Hash::convert_hash_to_string(hash);

    auto target_path = data_dir / hash_str;

    if (fs::is_regular_file(target_path)){
      std::cerr << "Skip " << target_path << ". File exists\n";
      return target_path;
    }

    // attempt reflink copy first
    bool reflink_success = false;
    if (rl == reflink::automatic || rl == reflink::always) {
      reflink_success = copy_reflink(path, target_path);
      if (rl == reflink::always && !reflink_success)
        throw std::runtime_error("Reflink copy failed");
    }

    if (!reflink_success) {
      fs::copy(path, target_path, fs::copy_options::overwrite_existing);
    }

    seal_file(target_path);

    return target_path;
  }

  fs::path Store::put(const std::string& content, std::string& hash_str){

    bool clear = false;
    auto callback = [&](size_t& size){
      if (clear) {
        const char* null = nullptr;
        size = 0;
        return null;
      }
      size = content.length();
      clear = true;
      return reinterpret_cast<const char*>(content.data());
    };

    auto target_path = put_stream(callback, hash_str);
    return target_path;
  }

  fs::path Store::put_stream(std::function<const char*(size_t&)> callback, std::string& hash_str){
    Hash hash;
    fs::path tmp_file(data_dir / "tmpfile"); //FIXME: create a random file name
    std::ofstream ofile(tmp_file);

    while (true) {
      size_t buf_size;
      const char* buf = callback(buf_size);

      if (buf_size == 0) break;
      ofile.write(buf, buf_size);
      hash.update(buf, buf_size);
    }
    ofile.close();
    hash_str = hash.get_hash_string();

    fs::path target(data_dir / hash_str);

    if (!fs::exists(target)) {
      fs::rename(tmp_file, target);
      seal_file(target);
    } else
      fs::remove(tmp_file);

    return target;
  }

  fs::path Store::move_to_store(const fs::path& path, std::string& hash_str, bool add_gc_root, reflink rl) {
    const fs::path target_path = copy_to_store(path, hash_str, rl);

    fs::remove(path);

    create_store_link(path, hash_str);

    if (add_gc_root){
      register_gc_link(path, hash_str);
    }

    return target_path;
  }

  void Store::create_store_link(const fs::path& link, const std::string& hash){
    if (path_coincides_with_store(link))
      throw std::invalid_argument("Link can not be in store's data directory");

    const fs::path target_path(data_dir / hash);

    if (!fs::exists(target_path))
      throw std::runtime_error("target path does not exist in store");

    if (fs::exists(link))
      throw std::runtime_error("Can not create link. File exists");

    // Caculate link target relative to link
    auto link_target = fs::relative(target_path, link.has_parent_path() ? link.parent_path() : fs::current_path());
    fs::create_symlink(link_target , link);
  }

  void Store::register_gc_link(const fs::path& target, const std::string& hash){
    auto gc_dir = gcroot_dir / hash;
    if (!fs::exists(gc_dir))
      fs::create_directory(gc_dir);

    // Calculate gc link target
    const fs::path link_target = fs::proximate(fs::current_path(), gc_dir) / target;

    // hash link name and point to target
    Hash link_hash;
    link_hash.update(link_target.string());
    auto link_gc_hash = gc_dir / link_hash.get_hash_string();

    if (!fs::exists(link_gc_hash))
      fs::create_symlink(link_target, link_gc_hash);
  }

  Hash::hash_t Store::calc_file_hash(const fs::path& file_name){
    Hash hash;

    std::ifstream file(file_name, std::ios::binary);
    if (!file.is_open())
      throw std::runtime_error("Can not open file");

    std::vector<char> buf(block_size);

    while (!file.eof() && buf.size() == block_size) {
      auto last_read = block_size;
      file.read(buf.data(), block_size);

      if (!file)
        last_read = file.gcount();

      buf.resize(last_read);
      hash.update(buf.data(), last_read);
    }

    file.close();

    return hash.get_hash_binary();
  }

  void Store::collect_garbage(){

    // loop over gc-root directories
    for (auto const& entry : fs::directory_iterator{gcroot_dir}) {

      // Only sub directories are allowed
      if (!fs::is_directory(entry.path()))
        fs::remove(entry.path());

      // loop over gc links
      for (auto const& link : fs::directory_iterator{gcroot_dir / entry.path().filename() }) {
        // Only symlink are allowed
        if (!fs::is_symlink(link.path())) {
          fs::remove(link.path());
          continue;
        }

        // get target location: FIXME this breaks down if symlink is not relative
        const auto target = entry.path() / fs::read_symlink(link.path());

        // check if link target is still alive
        if (!fs::is_symlink(target)) {
          fs::remove(link.path());
          continue;
        }

        // check if link target points to anything
        if (!fs::exists(fs::read_symlink(target))) {
          fs::remove(link.path());
          continue;
        }

        // check if link loops back to correct entry
        const auto target_resolve = fs::read_symlink(target);
        if (target_resolve.filename() != entry.path().filename() || !path_coincides_with_store(target_resolve)) {
          fs::remove(link.path());
          continue;
        }
      }

      // Remove actual gc-root dir and data file
      if (fs::is_empty(entry.path())) {
        const fs::path target = data_dir / entry.path().filename();
        fs::permissions(target, fs::perms::owner_write, fs::perm_options::add);
        fs::remove(target);
        fs::remove(entry.path());
      }
    }

    // find orphans in data directory
    for (auto const& entry : fs::directory_iterator{data_dir}) {
      if (!fs::exists(gcroot_dir / entry.path().filename())) {
        fs::permissions(entry.path(), fs::perms::owner_write, fs::perm_options::add);
        fs::remove(entry.path());
      }
    }
  }

  bool Store::verify_store() {
    if (!store_fs_is_valid()) {
      std::cerr << "Store file system layout invalid\n";
      return false;
    }

    // Check data directory
    bool valid = true;
    for (auto const& entry : fs::directory_iterator{data_dir}) {
      fs::file_status status = fs::status(entry.path());

      if (status.type() != fs::file_type::regular) {
        std::cerr << "Not a regular file: " << entry.path() << std::endl;
        valid = false;
        continue;
      }

      fs::perms permissions = status.permissions();
      if ((permissions & (fs::perms::owner_write | fs::perms::group_write | fs::perms::others_write )) != fs::perms::none) {
        std::cerr << "File is writable: " << entry.path() << std::endl;
        valid = false;
      }

      Hash::hash_t hash_bin = calc_file_hash(entry.path());
      if (Hash::convert_hash_to_string(hash_bin) != entry.path().filename()) {
        std::cerr << "Hash mismatch: " << entry.path() << std::endl;
        valid = false;
      }

    }
    return valid;
  }
}
