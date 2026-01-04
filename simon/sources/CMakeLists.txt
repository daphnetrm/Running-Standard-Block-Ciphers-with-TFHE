set(TFHE_PREFIX /home/admin-lcyl/tfhe)
set(APP_NAME simon)
set(SOME_NAME simon)
set(MAIN1 ${CMAKE_CURRENT_LIST_DIR}/main.cpp)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

set(APP_SRCS
  ${CMAKE_CURRENT_LIST_DIR}/main.cpp
  ${CMAKE_CURRENT_LIST_DIR}/simon.cpp
  ${CMAKE_CURRENT_LIST_DIR}/tables.cpp
  ${CMAKE_CURRENT_LIST_DIR}/key_schedule.cpp
  ${CMAKE_CURRENT_LIST_DIR}/base_b_keyswitch.cpp
  ${CMAKE_CURRENT_LIST_DIR}/base_b_keyswitchkey.cpp
  ${CMAKE_CURRENT_LIST_DIR}/bootstrapping.cpp
  ${CMAKE_CURRENT_LIST_DIR}/tlwe-functions-extra.cpp
  ${CMAKE_CURRENT_LIST_DIR}/tlwekeyswitch.cpp
  )

set(APP_HEADERS
  ${CMAKE_CURRENT_LIST_DIR}/simon.h
  ${CMAKE_CURRENT_LIST_DIR}/tables.h
  ${CMAKE_CURRENT_LIST_DIR}/key_schedule.h
  ${CMAKE_CURRENT_LIST_DIR}/base_b_keyswitch.h
  ${CMAKE_CURRENT_LIST_DIR}/base_b_keyswitchkey.h
  ${CMAKE_CURRENT_LIST_DIR}/bootstrapping.h
    ${CMAKE_CURRENT_LIST_DIR}/tlwe-functions-extra.h
  ${CMAKE_CURRENT_LIST_DIR}/tlwekeyswitch.h

  )




add_executable(${APP_NAME} ${APP_SRCS} ${MAIN1} ${APP_HEADERS})

include_directories(${TFHE_PREFIX}/src/include)


find_package(OpenMP)
#OpenMP::OpenMP_CXX

#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pg -g -fopenmp")
#set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pg -g -fopenmp")
#set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -pg -g -fopenmp")

# Link TFHE library: do not forget to update LD_LIBRARY_PATH with the path to tfhelib
# export LD_LIBRARY_PATH="$LD_PATH_LIBRARY:${TFHE_PREFIX}/lib"
target_link_libraries(${APP_NAME} ${TFHE_PREFIX}/build/libtfhe/libtfhe-spqlios-avx.so OpenMP::OpenMP_CXX)
target_link_libraries(${SOME_NAME} ${TFHE_PREFIX}/build/libtfhe/libtfhe-spqlios-avx.so OpenMP::OpenMP_CXX)

set_target_properties(${APP_NAME}
  PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
  )

