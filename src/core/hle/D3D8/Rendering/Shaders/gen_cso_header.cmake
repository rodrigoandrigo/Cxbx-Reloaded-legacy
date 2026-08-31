# gen_cso_header.cmake — Convert a compiled shader binary (.cso) to a C byte array header.
# Usage: cmake -DCSO_FILE=path/to/shader.cso -DHEADER_FILE=path/to/output.h
#              -DARRAY_NAME=shader_name -P gen_cso_header.cmake

file(READ "${CSO_FILE}" CSO_DATA HEX)
string(LENGTH "${CSO_DATA}" CSO_HEX_LEN)
math(EXPR CSO_BYTE_COUNT "${CSO_HEX_LEN} / 2")

# Build the unsigned-char array in one pass. Appending once per byte makes
# large shader blobs quadratic and can stall CMake for several minutes.
string(REGEX REPLACE "([0-9a-f][0-9a-f])" "0x\\1," ARRAY_BODY "${CSO_DATA}")

file(WRITE "${HEADER_FILE}"
"// Auto-generated from ${CSO_FILE} — do not edit.\n"
"#pragma once\n"
"#include <cstddef>\n"
"static const unsigned char ${ARRAY_NAME}[] = {\n"
"    ${ARRAY_BODY}\n"
"};\n"
"static const size_t ${ARRAY_NAME}_size = ${CSO_BYTE_COUNT};\n"
)
