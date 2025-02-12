// SPDX-FileCopyrightText: 2025 Markus Kowalewski
//
// SPDX-License-Identifier: GPL-3.0-only

#include <string>
#include <vector>
#include <openssl/sha.h>
#include <openssl/evp.h>


namespace scas {

  /**
   * Handle SHA256 calculation
   */
  class Hash {
    private:
      EVP_MD_CTX* ctx;

      void init();
      void clear();

    public:
      typedef std::vector<unsigned char> hash_t;

      Hash();
      ~Hash();

      int get_hash_length() { return SHA256_DIGEST_LENGTH; };

      void update(const std::string& input);
      void update(const char* input, size_t n);
      hash_t get_hash_binary();
      std::string get_hash_string();

      static std::string convert_hash_to_string(const hash_t& hash);
      static hash_t convert_string_to_hash(const std::string& string_hash);

      static std::string bytes_to_hex(const hash_t& hash);
      static hash_t hex_to_bytes(const std::string& string_hash);

      static std::string base64_to_hex(const std::string& b64_str);
      static std::string hex_to_base64(const std::string& hex_str);

      static std::string base64_encode(const hash_t& str);
      static hash_t base64_decode(const std::string& str);
  };
}
