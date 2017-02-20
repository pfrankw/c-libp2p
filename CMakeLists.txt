cmake_minimum_required( VERSION 2.8 )

project( p2p )

SET( EXECUTABLE_OUTPUT_PATH ${CMAKE_SOURCE_DIR}/build/bin )
SET( LIBRARY_OUTPUT_PATH ${CMAKE_SOURCE_DIR}/build/lib )

SET( CMAKE_C_FLAGS  "${CMAKE_C_FLAGS} -Wall" )
SET( CMAKE_C_FLAGS_DEBUG  "${CMAKE_C_FLAGS_DEBUG}" )
SET( CMAKE_C_FLAGS_RELEASE  "${CMAKE_C_FLAGS_RELEASE}" )

if( NOT CMAKE_BUILD_TYPE )
  SET( CMAKE_BUILD_TYPE "RELEASE" )
endif()

message( "Current CMake build type is ${CMAKE_BUILD_TYPE}" )

include_directories(
  include
  /usr/local/include
)

add_subdirectory( src )
#add_subdirectory( programs )

install( DIRECTORY "${CMAKE_SOURCE_DIR}/include/p2p" DESTINATION include )
