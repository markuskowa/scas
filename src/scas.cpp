// SPDX-FileCopyrightText: 2025 Markus Kowalewski
//
// SPDX-License-Identifier: GPL-3.0-only

#include "unistd.h"
#include <iostream>

#include "store.h"


void show_help(const std::string& arg0) {
  using namespace std;

  const string basename = filesystem::path(arg0).filename();
  cout << "Simple content addressed storage utility" << endl;
  cout << "" << endl;
  cout << "Usage:" << endl;
  cout << "" << endl;
  cout << "- Create a new store directory structure:" << endl;
  cout << "  " << basename << " init <new_store_directory>" << endl;
  cout << "" << endl;
  cout << "- Add file to the store:" << endl;
  cout << "  " << basename << " add -d store directory [-s] [file(s) to add]" << endl;
  cout << "" << endl;
  cout << "  -d directory  specify store path" << endl;
  cout << "  -s            move file to store and create gc protected symlink" << endl;
  cout << "  If no file name is give input from stdin is read" << endl;
  cout << "" << endl;
  cout << "- Create link point to content:" << endl;
  cout << "  " << basename << " link -d store directory [-s] <linkname> <hash>" << endl;
  cout << "  -d directory  specify store path" << endl;
  cout << "  -s            create gc protected symlink" << endl;
  cout << "" << endl;
  cout << "- Run garbage collection:" << endl;
  cout << "  " << basename << " gc <store directory>" << endl;
  exit(EXIT_FAILURE);
}

void command_init(const std::filesystem::path& dir) {
  scas::Store store(dir);
  store.create_store_fs();
}

void command_add(int argc, char **argv){
  int opt = 0;
  fs::path dir;
  bool symlink = false;

  while ((opt = getopt(argc, argv, "sd:")) != -1) {
    switch (opt) {
      case 'd':
        dir = optarg;
        break;
      case 's':
        symlink = true;
        break;
      default:
        show_help(argv[0]);
    };
  }

  if (dir.empty()) show_help(argv[0]);
  scas::Store store(dir);

  if (optind == argc) { // stdin
    if (symlink) show_help(argv[0]); // does not make sense

    const size_t bufsize = 64*1024*1024;

    std::string hash_str;
    std::string buffer;
    buffer.reserve(bufsize);

    auto callback = [&](size_t& size){
          std::cin.read(buffer.data(), bufsize);
          size = std::cin.gcount();
          return buffer.data();
    };

    const auto path = store.put_stream(callback, hash_str);

    std::cout << "created " << path << " (" << hash_str << ")" << std::endl;
  } else {
    for (; optind < argc; optind++){
      std::string hash;
      fs::path path;
      if (symlink)
        path = store.move_to_store(argv[optind], hash);
      else
        path = store.copy_to_store(argv[optind], hash);

      std::cout << "created " << path << " (" << scas::Hash::base64_to_hex(hash) << ")" << std::endl;
    }
  }

}

void command_link(int argc, char **argv) {
  int opt = 0;
  fs::path dir;
  bool gclink = false;

  while ((opt = getopt(argc, argv, "sd:")) != -1) {
    switch (opt) {
      case 'd':
        dir = optarg;
        break;
      case 's':
        gclink = true;
        break;
      default:
        show_help(argv[0]);
    };
  }

  if (dir.empty()) show_help(argv[0]);
  scas::Store store(dir);

  if (optind + 2 != argc) show_help(argv[0]);

  store.create_store_link(argv[optind], argv[optind+1]);
  if (gclink)
    store.register_gc_link(argv[optind], argv[optind+1]);

  std::cout << "linked " << argv[optind] << " (" << scas::Hash::base64_to_hex(argv[optind+1]) << ")" << std::endl;
}

void command_gc(const std::filesystem::path& dir){
  scas::Store store(dir);
  store.collect_garbage();
}


int main(int argc, char** argv) {
  fs::path dir("dstore");

  if (argc == 1) show_help(argv[0]);

  try {
  if (std::string(argv[1]) == "init") {
    if (argc != 3) show_help(argv[0]);
    command_init(argv[2]);
  } else if(std::string(argv[1]) == "add") {
    if (argc < 3) show_help(argv[0]);
    optind = 2;
    command_add(argc, argv);
  } else if(std::string(argv[1]) == "gc") {
    if (argc != 3) show_help(argv[0]);
    command_gc(argv[2]);
  } else if(std::string(argv[1]) == "link") {
    optind = 2;
    command_link(argc, argv);
  } else
    show_help(argv[0]);
  } catch (const std::exception& e) {
    std::cout << e.what() << std::endl;
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
