cmake_minimum_required(VERSION 3.10.0)
project(funchook VERSION 1.0.0)

find_package(PkgConfig)
pkg_check_modules(CAPSTONE REQUIRED capstone)

include(CTest)
enable_testing()

add_executable(funchook main.cc)

target_link_libraries(${PROJECT_NAME}
  PRIVATE
    ${CAPSTONE_LIBRARIES}
)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
