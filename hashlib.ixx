module;

#define CCAT_BUILD_MODULE

export module ccat.hashlib;

#pragma warning(push)
#pragma warning(disable : 5244)

#include "md5.hpp";
#include "sha1.hpp";
#include "sha224_and_sha256.hpp";
#include "sha384_and_sha512.hpp";

#pragma warning(pop)
