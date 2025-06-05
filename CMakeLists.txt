cmake_minimum_required(VERSION 3.00)

project(scas VERSION 0.2)
include(CTest)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
find_package(Catch2 3 REQUIRED)

add_library(scas SHARED src/scas.cpp src/hash.cpp src/store.cpp)

target_link_libraries(scas PRIVATE ${OPENSSL_LIBRARIES})
target_include_directories(scas PRIVATE ${OPENSSL_INCLUDE_DIRS})

install(TARGETS scas
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    PUBLIC_HEADER DESTINATION include
)

install(FILES src/hash.h src/store.h DESTINATION include)

add_executable(base_test src/hash_test.cpp src/store_test.cpp)
target_link_libraries(base_test PRIVATE Catch2::Catch2WithMain scas)
target_include_directories(base_test PRIVATE ${CATCH2_INCLUDE_DIRS})
add_test(NAME base_test COMMAND base_test)

add_executable(scas_exe src/scas.cpp)
target_link_libraries(scas_exe PRIVATE scas)
set_property(TARGET scas_exe PROPERTY OUTPUT_NAME scas)

install(TARGETS scas_exe
  RUNTIME DESTINATION bin
)
