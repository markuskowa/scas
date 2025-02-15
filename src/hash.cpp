// SPDX-FileCopyrightText: 2025 Markus Kowalewski
//
// SPDX-License-Identifier: GPL-3.0-only

#include <cctype>
#include <cstddef>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>

#include <openssl/bio.h>

#include "hash.h"

namespace scas {

  Hash::Hash() : ctx(nullptr) {
    init();
  };

  Hash::~Hash() {
    clear();
  }

  void Hash::clear() {
      if (ctx)
        EVP_MD_CTX_free(ctx);
      ctx = nullptr;
  }

  void Hash::init() {
    ctx = EVP_MD_CTX_new();
    if (!ctx)
      throw(std::runtime_error("EVP_MD_CTX_new failed"));

    if (EVP_DigestInit_ex(ctx, digest_type, nullptr) != 1) {
      clear();
      throw(std::runtime_error("EVP_DigestInit_ex failed"));
    }
  }

  void Hash::update(const char* input, size_t n){
    if (!ctx) init();

    if (EVP_DigestUpdate(ctx, input, n) != 1) {
      clear();
      throw(std::runtime_error("EVP_DigestUpdate failed"));
    }
  }

  void Hash::update(const std::string& input) {
    update(input.c_str(), input.length());
  }

  Hash::hash_t Hash::get_hash_binary(){
    unsigned int len = 0;
    hash_t hash(digest_length);

    if (EVP_DigestFinal_ex(ctx, hash.data(), &len) != 1) {
      clear();
      throw(std::runtime_error("EVP_DigestFinal_ex failed"));
    }

    clear();
    init();
    return(hash);
  }

  std::string Hash::get_hash_string(){
    auto hash = get_hash_binary();
    return convert_hash_to_string(hash);
  }

  std::string Hash::convert_hash_to_string(const hash_t& hash){
    if (hash.size() != digest_length)
      throw std::invalid_argument("Invalid hash length");

    return base64_encode(hash);
  }

  Hash::hash_t Hash::convert_string_to_hash(const std::string& string_hash){
    hash_t hash = base64_decode(string_hash);

    if (hash.size() != digest_length ) {
      throw std::invalid_argument("base64 encoded string length mismatched");
    }

    return hash;
  }

  std::string Hash::bytes_to_hex(const hash_t& hash){
    std::stringstream ss;

    for (int i = 0; i < hash.size(); i++) {
      ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }

    return ss.str();
  }

  Hash::hash_t Hash::hex_to_bytes(const std::string& string_hash){
    if (string_hash.length() % 2 != 0)
      throw std::invalid_argument("Hex string length mismatched");


    hash_t binary_hash;
    binary_hash.reserve(digest_length);

    for (size_t i = 0; i < string_hash.length(); i += 2) {
        std::string byte_str = string_hash.substr(i, 2);

        if (!std::isxdigit(byte_str[0]) || !std::isxdigit(byte_str[1])) {
            throw std::invalid_argument("Invalid hex characters in string.");
        }

        unsigned int byte;  // needs to be int
        std::istringstream ss(byte_str);
        ss >> std::hex >> byte;

        binary_hash.push_back(byte);
    }

    return binary_hash;
  }

  std::string Hash::base64_to_hex(const std::string& b64_str){
    return bytes_to_hex(base64_decode(b64_str));
  }

  std::string Hash::hex_to_base64(const std::string& hex_str){
    return base64_encode(hex_to_bytes(hex_str));
  }

  std::string Hash::base64_encode(const hash_t& data){
    if (data.empty()) {
        return ""; // Handle empty input
    }

    int encoded_len = (data.size() + 2) / 3 * 4; // Calculate encoded length (important!)
    std::string encoded(encoded_len, '\0');

    auto ol = EVP_EncodeBlock(
        reinterpret_cast<unsigned char*>(encoded.data()),
        reinterpret_cast<const unsigned char*>(data.data()),
        data.size());

    if (ol != encoded_len)
      throw std::runtime_error("B64 encode failed");

    // make fs proof
    std::replace(encoded.begin(), encoded.end(), '/', '-');

    return encoded;
  }

  Hash::hash_t Hash::base64_decode(const std::string& base64_str) {
    if (base64_str.empty()) {
        return {};
    }

    std::string encoded(base64_str);
    std::replace(encoded.begin(), encoded.end(), '-', '/');

    int decoded_len = encoded.length();
    hash_t decoded;
    decoded.resize(decoded_len);


    EVP_ENCODE_CTX *ctx;
    ctx = EVP_ENCODE_CTX_new();
    EVP_EncodeInit(ctx);

    int olength = 0;
    int ret = 0;
    ret = EVP_DecodeUpdate(ctx,
        decoded.data(), &olength,
        reinterpret_cast<const unsigned char*>(encoded.data()), encoded.size());

    if (ret < 0){ // Invalid chars
      EVP_ENCODE_CTX_free(ctx);
      throw std::runtime_error("base64 decode failed. Invalid characters.");
    }

    if (ret == 1){ // final pad "=" missing
      EVP_ENCODE_CTX_free(ctx);
      throw std::runtime_error("base64 decode failed. Missing padding character =.");
    }

    unsigned char buf[4]; // unprocessed data, max 4 bytes.
    int buf_len = 0;
    // This should not yield any useful data, but only serve as an error check
    ret = EVP_DecodeFinal(ctx, buf, &buf_len);

    if (ret < 0){ // Data incomplete
      EVP_ENCODE_CTX_free(ctx);
      throw std::runtime_error("base64 decode failed. Data incomplete.");
    }

    decoded.resize(olength);
    EVP_ENCODE_CTX_free(ctx);

    return decoded;
  }

}
