#----------------------------------------------------------------
# Generated CMake target import file.
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "ScopePact::scopepact_envelope" for configuration ""
set_property(TARGET ScopePact::scopepact_envelope APPEND PROPERTY IMPORTED_CONFIGURATIONS NOCONFIG)
set_target_properties(ScopePact::scopepact_envelope PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_NOCONFIG "CXX"
  IMPORTED_LOCATION_NOCONFIG "${_IMPORT_PREFIX}/lib/libscopepact_envelope.a"
  )

list(APPEND _cmake_import_check_targets ScopePact::scopepact_envelope )
list(APPEND _cmake_import_check_files_for_ScopePact::scopepact_envelope "${_IMPORT_PREFIX}/lib/libscopepact_envelope.a" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
