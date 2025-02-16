// SPDX-FileCopyrightText: 2025 Markus Kowalewski
//
// SPDX-License-Identifier: GPL-3.0-only

#include "hash.h"
#include <catch2/catch_test_macros.hpp>

#include <iostream>

TEST_CASE("hex en/decoding","[hash]"){
  const scas::Hash::hash_t binary{0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0};
  std::string str(scas::Hash::get_hash_length()*2, '0');
  str.replace(0, 17, "00123456789abcdef");
  REQUIRE( scas::Hash::bytes_to_hex(binary) == str);
  REQUIRE( scas::Hash::bytes_to_hex(scas::Hash::hex_to_bytes(str)) == str);

  // Uneven number of nibbles
  REQUIRE_THROWS ( scas::Hash::hex_to_bytes("1") );

  // Invalid characters
  REQUIRE_THROWS ( scas::Hash::hex_to_bytes("gg") );
}

TEST_CASE("base64 coding","[hash]"){
  const scas::Hash::hash_t clear_text_bin{0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};
  const std::string base64_text("47DEQpj8HBSa+-TImW+5JCeuQeRkm5NMpJWZG3hSuFU=");

  REQUIRE( scas::Hash::base64_encode(clear_text_bin) == base64_text );
  REQUIRE( clear_text_bin == scas::Hash::base64_decode(base64_text) );

  // wrong length
  REQUIRE_THROWS( scas::Hash::base64_decode("47DEQpj8HBSa+-TImW+5JCeuQeRkm5NMpJWZG3hSu=") );

  // invalid chars
  REQUIRE_THROWS( scas::Hash::base64_decode("!?DEQpj8HBSa+-TImW+5JCeuQeRkm5NMpJWZG3hSuFU=") );

  // no padding
  REQUIRE_THROWS( scas::Hash::base64_decode("47DEQpj8HBSa+-TImW+5JCeuQeRkm5NMpJWZG3hSuFU") );
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

  REQUIRE_THROWS(scas::Hash::convert_string_to_hash(deficient_hash_str) );
}

