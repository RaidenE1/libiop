add_library(
  iop

  common/common.cpp
  
  bcs/hashing/blake2b.cpp
  protocols/ldt/ldt_reducer.cpp
  protocols/ldt/fri/fri_ldt.cpp
  protocols/ldt/fri/fri_aux.cpp
  relations/sparse_matrix.cpp
  iop/utilities/batching.cpp
  algebra/utils.cpp
)

# Cmake find modules
list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

find_package(sodium)

target_link_libraries(
  iop

  sodium

  ff
)

target_include_directories(
  iop

  PUBLIC
  ../depends/libfqfft
  ../depends/libff
)

# TESTS

include(CTest)

# snark

add_executable(test_aurora_snark tests/snark/test_aurora_snark.cpp)
target_link_libraries(test_aurora_snark iop gtest_main)
add_test(
  NAME test_aurora_snark
  COMMAND test_aurora_snark
)
