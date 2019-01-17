set(FIND_CRYPTOPP_PATHS
        ~/Library/Frameworks/crypto)

find_path(CRYPTOPP_INCLUDE_DIR hex.h
        PATH_SUFFIXES include
        PATHS ${FIND_CRYPTOPP_PATHS})

find_library(CRYPTOPP_LIBRARY
        NAMES cryptopp
        PATH_SUFFIXES lib
        PATHS ${FIND_CRYPTOPP_PATHS})