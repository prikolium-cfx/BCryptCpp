cmake_minimum_required(VERSION 3.16)

project(bcrypt 
    VERSION 1.0.0
    DESCRIPTION "A C++ port of jBCrypt Library"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(BCRYPT_SOURCES
    src/bcrypt.cpp
)

set(BCRYPT_HEADERS
    include/bcrypt.h
)

add_library(bcrypt STATIC ${BCRYPT_SOURCES} ${BCRYPT_HEADERS})

target_include_directories(BCrypt 
    PUBLIC 
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include/bcrypt>
)

set_target_properties(BCrypt PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    PUBLIC_HEADER "${BCRYPT_HEADERS}"
)

option(BUILD_TESTS "Build test programs" ON)

if(BUILD_TESTS)
    enable_testing()
    
    add_executable(bcryptTests Test.cpp)
    target_link_libraries(bcryptTests BCrypt)
    target_include_directories(bcryptTests PRIVATE include)
    
    add_test(NAME bcryptTests COMMAND BCryptTests)
endif()

include(GNUInstallDirs)

install(TARGETS bcrypt
    EXPORT bcryptTargets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/bcrypt
)

install(EXPORT bcryptTargets
    FILE bcryptTargets.cmake
    NAMESPACE BCrypt::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/bcrypt
)

include(CMakePackageConfigHelpers)

file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/bcryptConfig.cmake" "
include(CMakeFindDependencyMacro)
include(\"\${CMAKE_CURRENT_LIST_DIR}/bcryptTargets.cmake\")
")

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/bcryptConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/bcryptConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/bcryptConfigVersion.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/bcrypt
)
