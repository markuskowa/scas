// SPDX-FileCopyrightText: 2025 Markus Kowalewski
//
// SPDX-License-Identifier: GPL-3.0-only

#include "store.h"
#include <catch2/catch_test_macros.hpp>
#include <fstream>


void helper_create_file(const std::string& ofname, const std::string& ofcontent){
  std::ofstream ofile(ofname, std::ios::trunc);
  ofile << ofcontent;
  ofile.close();
}

TEST_CASE("Store creation", "[store]") {
  scas::Store store("empty_store");
  REQUIRE_NOTHROW( store.create_store_fs() );

  REQUIRE( fs::is_directory("empty_store/data") );
  REQUIRE( fs::is_directory("empty_store/gc-roots") );
  REQUIRE( store.store_fs_is_valid() );

  REQUIRE_THROWS( store.create_store_fs() );

  fs::remove_all(store.get_dir());
}


SCENARIO("Store creation and operation", "[store]") {
  GIVEN("An empty store") {
    scas::Store store("op_store");
    REQUIRE_NOTHROW( store.create_store_fs() );
    REQUIRE( store.store_fs_is_valid() );

    WHEN("Place content directly") {
      std::string hash;
      auto target = store.put("my direct content", hash);

      THEN("Content is present in store") {
        REQUIRE( fs::exists(target) );
        REQUIRE( scas::Hash::convert_hash_to_string(scas::Store::calc_file_hash(target)) == hash);
        REQUIRE( store.file_is_in_store(hash) );
        REQUIRE( !store.file_is_in_store("no-valid-hash") );

        REQUIRE( store.path_coincides_with_store(target) );
        REQUIRE( !store.path_coincides_with_store(store.get_dir()) ); // top-level is not in data dir
      }

    }

    WHEN( "Add file to store, link original" ) {
      const std::string ofname("gc_file_a");
      const std::string ofcontent("a");
      helper_create_file(ofname, ofcontent);

      scas::Hash hash;
      hash.update(ofcontent);
      const std::string hash_str = hash.get_hash_string();

      REQUIRE( !fs::is_regular_file(store.get_dir() / "data" / hash_str) );

      std::string hash_ref;
      REQUIRE_NOTHROW( store.move_to_store(ofname, hash_ref) );
      REQUIRE( hash_ref == hash_str );
      REQUIRE( store.file_is_in_store(ofname) );
      REQUIRE( store.get_hash_from_path(ofname) == hash_str );

      THEN("Store is recognized as valid") {
        REQUIRE( store.verify_store() );
      }

      THEN("data is present and linked to store") {
        REQUIRE( fs::is_regular_file(store.get_dir() / "data" / hash_str) );
        REQUIRE( fs::is_symlink(ofname) );
        REQUIRE( fs::read_symlink(ofname) == store.get_dir() / "data" / hash_str );
        REQUIRE( (fs::status(store.get_dir() / "data" / hash_str).permissions()
              & (fs::perms::owner_write | fs::perms::group_write | fs::perms::others_write )) == fs::perms::none );
      }

      THEN("gc-root has been created and points to linked file") {
        REQUIRE( fs::is_directory(store.get_dir() / "gc-roots" / hash_str) );

        hash.update(fs::path("../../../") / ofname);
        const std::string link_name = hash.get_hash_string();

        REQUIRE( fs::is_symlink(store.get_dir() / "gc-roots" / hash_str / link_name) );
        REQUIRE( fs::read_symlink(store.get_dir() / "gc-roots" / hash_str / link_name).filename() == ofname );
      }

      fs::remove(ofname);
    }

    fs::remove_all(store.get_dir());
  }
}

SCENARIO("Store integrity", "[store]") {
  GIVEN("An a store with content") {
    scas::Store store("bad_store");
    REQUIRE_NOTHROW( store.create_store_fs() );
    REQUIRE( store.store_fs_is_valid() );

    const std::string fname = "myfile";
    helper_create_file(fname, "my content");
    std::string hash_str;
    REQUIRE_NOTHROW( store.move_to_store(fname, hash_str) );
    REQUIRE( store.verify_store() );

    const fs::path target = fs::read_symlink(fname);

    THEN("Data is writable") {
      fs::permissions(target, fs::perms::owner_write, fs::perm_options::add);
      REQUIRE(!store.verify_store());
    }

    THEN("Filename is corrupted") {
      fs::permissions(target, fs::perms::owner_write, fs::perm_options::add);
      fs::rename(target, fs::path(target) += fs::path("x"));
      fs::permissions(fs::path(target) += fs::path("x"), fs::perms::owner_write, fs::perm_options::remove);
      REQUIRE(!store.verify_store());
    }

    THEN("File content is corrupted") {
      fs::permissions(target, fs::perms::owner_write, fs::perm_options::add);
      helper_create_file(fname, "not my content");
      fs::permissions(target, fs::perms::owner_write, fs::perm_options::remove);
      REQUIRE(!store.verify_store());
    }

    THEN("Acct on in-store data") {
      std::string dummy;
      REQUIRE_THROWS(store.copy_to_store(store.get_dir() / "data" / hash_str, dummy));
      REQUIRE_THROWS(store.create_store_link(store.get_dir() / "data" / hash_str, hash_str));
    }

    THEN("Garbage collection: gc is valid") {
      REQUIRE_NOTHROW( store.collect_garbage() );
      REQUIRE( fs::exists(target) );
    }

    THEN("Garbage collection: link has been removed") {
      fs::remove(fname);
      REQUIRE_NOTHROW( store.collect_garbage() );
      REQUIRE( !fs::exists(target) );
    }

    THEN("Garbage collection: link points to wrong destination") {
      fs::remove(fname);
      fs::create_symlink(store.get_dir(), fname);
      REQUIRE_NOTHROW( store.collect_garbage() );
      REQUIRE( !fs::exists(target) );
    }

    THEN("Garbage collection: link points to void") {
      fs::remove(fname);
      fs::create_symlink("not_a_valid_target", fname);
      REQUIRE_NOTHROW( store.collect_garbage() );
      REQUIRE( !fs::exists(target) );
    }

    THEN("Garbage collection: clean up orphans") {
      std::string hash;
      auto target = store.put("my orphan content", hash);
      REQUIRE( fs::exists(target) );
      REQUIRE_NOTHROW( store.collect_garbage() );
      REQUIRE( !fs::exists(target) );
    }

    THEN("Link to hash manually") {
      std::string hash;
      auto target = store.put("my orphan content", hash);
      const fs::path link("my_link");
      fs::create_symlink(store.get_store_path(hash), link);
      store.register_gc_link(link, hash);
      REQUIRE_NOTHROW( store.collect_garbage() );
      REQUIRE( fs::exists(target) );
      fs::remove(link);
    }

    fs::remove(fname);
    fs::remove_all(store.get_dir());
  }
}
