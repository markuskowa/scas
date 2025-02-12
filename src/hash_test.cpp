// SPDX-FileCopyrightText: 2025 Markus Kowalewski
//
// SPDX-License-Identifier: GPL-3.0-only

#include "hash.h"
#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_vector.hpp>

#include <iostream>

TEST_CASE("hex en/decoding","[hash]"){
  const scas::Hash::hash_t binary{0x00, 0x11, 0x22, 0xaa};
  REQUIRE( scas::Hash::bytes_to_hex(binary) == "001122aa" );
  REQUIRE( scas::Hash::bytes_to_hex(scas::Hash::hex_to_bytes("0123456789abcdef")) == "0123456789abcdef");

  // Uneven number of nibbles
  REQUIRE_THROWS ( scas::Hash::hex_to_bytes("1") );

  // Invalid characters
  REQUIRE_THROWS ( scas::Hash::hex_to_bytes("gg") );
}

TEST_CASE("base64 coding","[hash]"){
  const scas::Hash::hash_t clear_text_bin{'s','i','m','p','l','e','\n'};
  const std::string base64_text("c2ltcGxlCg==");

  REQUIRE( scas::Hash::base64_encode(clear_text_bin) == base64_text );
  REQUIRE_THAT( clear_text_bin, Catch::Matchers::Equals(scas::Hash::base64_decode(base64_text)) );

  // wrong length
  REQUIRE_THROWS( scas::Hash::base64_decode("c2ltcxlCg==") );

  // invalid chars
  REQUIRE_THROWS( scas::Hash::base64_decode("c2ltc!xlCg==") );

  // no padding
  REQUIRE_THROWS( scas::Hash::base64_decode("c2ltcGxlCgcc") );
}

TEST_CASE("base64 <-> hex conversion","[hash]"){
  std::string empty_str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
  std::string empty_str_b64 = "47DEQpj8HBSa+-TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";

  REQUIRE( scas::Hash::base64_to_hex(empty_str_b64) == empty_str );
  REQUIRE( scas::Hash::hex_to_base64(empty_str) == empty_str_b64 );
}

TEST_CASE("Convert binary <-> string", "[hash]") {
  std::string hash_str = "47DEQpj8HBSa+-TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";

  scas::Hash::hash_t hash_bin;
  REQUIRE_NOTHROW( hash_bin = scas::Hash::convert_string_to_hash(hash_str) );
  REQUIRE( scas::Hash::convert_hash_to_string(hash_bin) == hash_str );
}

TEST_CASE("SHA256 - basic hashing", "[hash]") {
  std::string empty_str = "47DEQpj8HBSa+-TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";

  scas::Hash sha256;

  REQUIRE( sha256.get_hash_string() == empty_str );

  // Check that has function get re-initialized
  REQUIRE( sha256.get_hash_string() == empty_str );

  sha256.update("");
  std::string hash_empty = sha256.get_hash_string();
  REQUIRE( hash_empty  == empty_str );

  sha256.update("A");
  REQUIRE( sha256.get_hash_string() == "VZrq0IJk1XldOQlxjN0Fq9SVcuhP5VWQ7vMaiKCP3-0=" );

  sha256.update("AB");
  REQUIRE( sha256.get_hash_string() == "OBZPvRdgPXP2lri01yZk1zW7anyIV3aH-SrjP9aWQVM=" );
}


TEST_CASE("SHA256 - errors", "[hash]") {
  scas::Hash sha256;

  std::string deficient_hash_str("001122");
  std::vector<unsigned char> deficient_hash_bin = { 0x00, 0x11, 0x22 };

  REQUIRE_THROWS(scas::Hash::convert_hash_to_string(deficient_hash_bin) );
  REQUIRE_THROWS(scas::Hash::convert_string_to_hash(deficient_hash_str) );
}

