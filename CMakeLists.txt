cmake_minimum_required(VERSION 3.20)
project(fwlint CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

find_package(nlohmann_json CONFIG REQUIRED)

add_library(fwlint_core
    src/interval.cpp
    src/box.cpp
    src/model.cpp
    src/parser_json.cpp
    src/parser_cisco.cpp
    src/analysis.cpp
    src/simulate.cpp
    src/report_text.cpp
    src/report_json.cpp
    src/report_sarif.cpp
)
target_include_directories(fwlint_core PUBLIC include)
target_link_libraries(fwlint_core PUBLIC nlohmann_json::nlohmann_json)
if(MINGW)
    target_link_options(fwlint_core PUBLIC -static)
endif()

add_executable(fwlint src/main.cpp)
target_link_libraries(fwlint PRIVATE fwlint_core)

option(FWLINT_BUILD_TESTS "Build the fwlint unit test suite" ON)
if(FWLINT_BUILD_TESTS)
    find_package(Catch2 3 CONFIG REQUIRED)
    add_executable(fwlint_tests
        tests/test_interval.cpp
        tests/test_box.cpp
        tests/test_analysis.cpp
        tests/test_parsers.cpp
    )
    target_link_libraries(fwlint_tests PRIVATE fwlint_core Catch2::Catch2WithMain)

    enable_testing()
    include(CTest)
    add_test(NAME fwlint_tests COMMAND fwlint_tests)
endif()
