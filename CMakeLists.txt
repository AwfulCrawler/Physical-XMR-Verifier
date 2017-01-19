#Author: AwfulCrawler
#
# Parts of this project Copyright (c) 2014-2016, The Monero Project
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are
# permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of
#    conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list
#    of conditions and the following disclaimer in the documentation and/or other
#    materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors may be
#    used to endorse or promote products derived from this software without specific
#    prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
# THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
# THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

cmake_minimum_required(VERSION 2.8.7)

project(certificate_verifier)

function (die msg)
  if (NOT WIN32)
    string(ASCII 27 Esc)
    set(ColourReset "${Esc}[m")
    set(BoldRed     "${Esc}[1;31m")
  else ()
    set(ColourReset "")
    set(BoldRed     "")
  endif ()

  message(FATAL_ERROR "${BoldRed}${msg}${ColourReset}")
endfunction ()

#-----------------------------------------------------------------------------------------------------------------------

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -D_GNU_SOURCE -maes")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11 -D_GNU_SOURCE -maes")


#==============================================================
#
#LIBRARIES
#
#==============================================================
list(INSERT CMAKE_MODULE_PATH 0
  "${CMAKE_SOURCE_DIR}/cmake")


# find_package(Unbound REQUIRED)
# message(STATUS "Found libunbound include (unbound.h) in ${UNBOUND_INCLUDE_DIR}")
# if(UNBOUND_LIBRARIES)
#   message(STATUS "Found libunbound shared library")
#   set(UNBOUND_STATIC false)
#   set(UNBOUND_INCLUDE ${UNBOUND_INCLUDE_DIR})
#   set(UNBOUND_LIBRARY ${UNBOUND_LIBRARIES} )
#   set(UNBOUND_LIBRARY_DIRS "" )
# else()
#   die("Found libunbound includes, but could not find libunbound library. Please make sure you have installed libunbound or libunbound-dev or the equivalent")
# endif()
find_package(Unbound)

if(NOT UNBOUND_INCLUDE_DIR)
  set(UNBOUND_STATIC true)
  set(UNBOUND_INCLUDE "monero/external/unbound/libunbound")
  set(UNBOUND_LIBRARY "unbound")
  set(UNBOUND_LIBRARY_DIRS "monero/build/release/external/unbound")
else()
  message(STATUS "Found libunbound include (unbound.h) in ${UNBOUND_INCLUDE_DIR}")
  if(UNBOUND_LIBRARIES)
    message(STATUS "Found libunbound shared library")
    set(UNBOUND_STATIC false)
    set(UNBOUND_INCLUDE ${UNBOUND_INCLUDE_DIR})
    set(UNBOUND_LIBRARY ${UNBOUND_LIBRARIES})
    set(UNBOUND_LIBRARY_DIRS "")
  else()
    die("Found libunbound includes, but could not find libunbound library. Please make sure you have installed libunbound or libunbound-dev or the equivalent")
  endif()
endif()



find_package(OpenSSL REQUIRED)
#if(STATIC)
#  if(UNIX)
set(OPENSSL_LIBRARIES "${OPENSSL_LIBRARIES};${CMAKE_DL_LIBS}")
#  endif()
#endif()



find_package(Boost 1.58 QUIET REQUIRED COMPONENTS system filesystem thread date_time chrono regex serialization program_options)
if(NOT Boost_FOUND)
  die("Could not find Boost libraries, please make sure you have installed Boost or libboost-all-dev (1.58) or the equivalent")
endif()

set ( WALLET_LIB libwallet_merged.a )


include_directories(${OPENSSL_INCLUDE_DIR}
                    ${UNBOUND_INCLUDE}
                    monero/src
                    monero/contrib/epee/include
                    src)

link_directories( monero/lib
                  ${UNBOUND_LIBRARY_DIRS})


add_subdirectory(src)
