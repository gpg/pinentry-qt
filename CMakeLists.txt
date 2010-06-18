project(pinentry-qt)
cmake_minimum_required(VERSION 2.6.0)

set(PINENTRY_QT_VERSION_MAJOR "0")
set(PINENTRY_QT_VERSION_MINOR "8")
set(PINENTRY_QT_VERSION_PATCH "1")

set(PINENTRY_QT_VERSION "${PINENTRY_QT_VERSION_MAJOR}.${PINENTRY_QT_VERSION_MINOR}.${PINENTRY_QT_VERSION_PATCH}")

add_definitions(-DVERSION="${PINENTRY_QT_VERSION}")

# Checks
find_package(Qt4 REQUIRED)

include(CheckIncludeFiles)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)
add_definitions(-DHAVE_CONFIG_H=1)

if(WIN32)
add_definitions(-DHAVE_W32_SYSTEM=1)
add_definitions(-DHAVE_DOSISH_SYSTEM=1)
endif(WIN32)
if(WINCE)
add_definitions(-DHAVE_W32CE_SYSTEM=1)
endif(WINCE)

# Build rules
#   set(QT_USE_OPENGL TRUE)
include(${QT_USE_FILE})

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

set(pinentry_qt_SRCS
    qrc_pinentry.cpp   
    pinentrydialog.cpp
    main.cpp
    assuan-buffer.c
    assuan-defs.h
    assuan-errors.c
    assuan.h
    assuan-handler.c
    assuan-listen.c
    assuan-pipe-server.c
    assuan-util.c
    memory.h
    secmem-util.h
    secmem-util.c
    secmem.c
    pinentry.c
    getopt.h
    getopt.c
)

# Automatically figure out moc files.
qt4_automoc(${qtproject_SRCS})

add_executable(pinentry-qt ${pinentry_qt_SRCS})
target_link_libraries(pinentry-qt ${QT_LIBRARIES})

install(TARGETS pinentry-qt DESTINATION bin)


# Packaging
set(CPACK_PACKAGE_VENDOR "g10 Code GmbH")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Pinentry Qt4")
set(CPACK_PACKAGE_VERSION_MAJOR ${PINENTRY_QT_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${PINENTRY_QT_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${PINENTRY_QT_VERSION_PATCH})
if (APPLE)
#  set(CPACK_RESOURCE_FILE_README "${CMAKE_CURRENT_SOURCE_DIR}/cpack/README.txt")
#  set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/cpack/LICENSE.txt")
  set(CPACK_SET_DESTDIR ON)
  set(CPACK_PACKAGE_RELOCATABLE OFF)
endif (APPLE)
  
include(CPack)
