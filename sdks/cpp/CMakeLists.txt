cmake_minimum_required(VERSION 3.20)

project(scopepact_envelope VERSION 0.1.0 LANGUAGES CXX)

include(GNUInstallDirs)
find_package(OpenSSL 1.1.1 REQUIRED COMPONENTS Crypto)

add_library(scopepact_envelope src/envelope.cpp)
add_library(ScopePact::Envelope ALIAS scopepact_envelope)
target_compile_features(scopepact_envelope PUBLIC cxx_std_20)
target_include_directories(
  scopepact_envelope
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
target_link_libraries(scopepact_envelope PUBLIC OpenSSL::Crypto)

option(SCOPEPACT_BUILD_TESTS "Build the ScopePact C++ conformance test" ON)
if(SCOPEPACT_BUILD_TESTS)
  enable_testing()
  find_package(nlohmann_json 3.11 REQUIRED CONFIG)
  add_executable(scopepact_envelope_test tests/envelope_test.cpp)
  target_compile_features(scopepact_envelope_test PRIVATE cxx_std_20)
  target_link_libraries(
    scopepact_envelope_test
    PRIVATE ScopePact::Envelope nlohmann_json::nlohmann_json
  )
  target_compile_definitions(
    scopepact_envelope_test
    PRIVATE SCOPEPACT_VECTOR_PATH="${CMAKE_CURRENT_SOURCE_DIR}/../../conformance/vectors/envelope-v0.json"
  )
  add_test(NAME scopepact_envelope_vector COMMAND scopepact_envelope_test)
endif()

install(
  TARGETS scopepact_envelope
  EXPORT ScopePactEnvelopeTargets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(
  EXPORT ScopePactEnvelopeTargets
  NAMESPACE ScopePact::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ScopePactEnvelope
)
