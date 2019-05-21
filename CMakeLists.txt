    cmake_minimum_required(VERSION 3.7)

    project(pound_gitlab)


    SET(MAINFOLDER ${PROJECT_SOURCE_DIR})


    #if (NOT EXECUTABLE_OUTPUT_PATH)

    #    SET(EXECUTABLE_OUTPUT_PATH "${MAINFOLDER}/bin")

    #endif ()


    #add_definitions(-DVERSION=\"pound2.8a+zevenet5\" -DC_SSL=\"\" -DC_T_RSA=\"0\" -DC_DH_LEN=\"2048\" -DC_MAXBUF=\"16384\" -DC_OWNER=\"\" -DC_GROUP=\"\" -DC_SUPER=\"0\" -DC_CERT1L=\"\"  -Wstrict-prototypes -Wno-unused-result -pipe -pthread -DNEED_STACK -DHAVE_SYSLOG_H=1 -pthread -DDH_LEN=2048  -D_REENTRANT -D_THREAD_SAFE )

    add_definitions(-DVERSION=\"pound2.8a+zevenet5\" -DC_SSL=\"\" -DC_T_RSA=\"0\" -DC_DH_LEN=\"2048\" -DC_MAXBUF=\"16384\" -DC_OWNER=\"\" -DC_GROUP=\"\" -DC_SUPER=\"0\" -DC_CERT1L=\"\" -Wstrict-prototypes -Wno-unused-result -pipe -DNEED_STACK -DHAVE_SYSLOG_H=1 -DDH_LEN=2048 -DMAXBUF=16384 -D_REENTRANT -D_THREAD_SAFE) #
    add_definitions(-DWAF=1)

    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -lresolv -ldl -g -rdynamic  -lm ")

    #set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}  -D__FILENAME__='\"$(subst  ${CMAKE_SOURCE_DIR}/,,$(abspath $<))\"'")


    #if (NOT CMAKE_BUILD_TYPE)

    #    set(CMAKE_BUILD_TYPE Debug)

    #endif ()


    set(CMAKE_C_FLAGS_DEBUG "-g -rdynamic ")

    #set(CMAKE_C_FLAGS_RELEASE "-O2 ")


    find_package(PkgConfig)

    pkg_check_modules(PC_PCRE QUIET libpcre)

    set(PCRE_DEFINITIONS ${PC_PCRE_CFLAGS_OTHER})

    find_path(PCRE_INCLUDE_DIR pcre.h

            HINTS ${PC_PCRE_INCLUDEDIR} ${PC_PCRE_INCLUDE_DIRS}

            PATH_SUFFIXES pcre)


    find_library(PCRE_PCRE_LIBRARY NAMES pcre HINTS ${PC_PCRE_LIBDIR} ${PC_PCRE_LIBRARY_DIRS})


    find_library(PCRE_PCREPOSIX_LIBRARY NAMES pcreposix HINTS ${PC_PCRE_LIBDIR} ${PC_PCRE_LIBRARY_DIRS})


    include(FindPackageHandleStandardArgs)


    find_package_handle_standard_args(PCRE DEFAULT_MSG PCRE_INCLUDE_DIR PCRE_PCRE_LIBRARY PCRE_PCREPOSIX_LIBRARY)

    set(PCRE_LIBRARIES ${PCRE_PCREPOSIX_LIBRARY} ${PCRE_PCRE_LIBRARY})

    mark_as_advanced(PCRE_INCLUDE_DIR PCRE_LIBRARIES PCRE_PCRE_LIBRARY)


    # Search OpenSSL

    #find_package(PkgConfig REQUIRED)

    #pkg_search_module(OPENSSL REQUIRED openssl)


    #if (OPENSSL_FOUND)

    #  include_directories(${OPENSSL_INCLUDE_DIRS})

    #  message(STATUS "Using OpenSSL ${OPENSSL_VERSION}")

    #else ()

    #  # Error; with REQUIRED, pkg_search_module() will throw an error by it's own

    #endif ()


    find_package(PkgConfig REQUIRED)

    pkg_search_module(OPENSSL REQUIRED openssl)


    #if (OPENSSL_FOUND)

    #  status_message(STATUS "Openssl includes ${OPENSSL_INCLUDE_DIRS}")

    #  status_message(STATUS "Openssl link ${OPENSSL_LIBRARIES}")

    #  include_directories(${OPENSSL_INCLUDE_DIRS})

    #  status_message(STATUS "Using OpenSSL ${OPENSSL_VERSION}")

    #else ()

    #  # Error; with REQUIRED, pkg_search_module() will throw an error by it's own

    #endif ()

    #

    include_directories(/usr/include/openssl-1.1)

    include_directories(/usr/local/modsecurity/include)
    link_directories(/usr/local/modsecurity/lib)

    link_directories(/usr/lib/openssl-1.1)

    find_package(Threads)


    add_executable(${PROJECT_NAME}ctl

            poundctl.c

            )


    add_executable(${PROJECT_NAME}
            waf.c

            config.c

            config.h

            #    dh2048.h

#            dh512.h
#            dh1024.h

            http.c

            pound.c

            pound.h

            pound_sync.c

            pound_sync.h

            pound_sync_enum.h

            svc.c

            svc.h

            version.c

            )


    target_link_libraries(${PROJECT_NAME} ${PCRE_LIBRARIES} ${OPENSSL_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} libmodsecurity.so)
