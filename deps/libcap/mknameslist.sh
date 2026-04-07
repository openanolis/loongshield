#!/bin/sh

NAMESLIST=cap_names.list.h
UAPI_HEADER=include/uapi/linux/capability.h

echo "=> making ${NAMESLIST} from ${UAPI_HEADER}"


grep -E '^#define\s+CAP_([^\s]+)\s+[0-9]+\s*$' ${UAPI_HEADER} | \
    sed -e 's/^#define\s\+/{"/' \
        -e 's/\s*$/},/' \
        -e 's/\s\+/",/' \
        -e 'y/ABCDEFGHIJKLMNOPQRSTUVWXYZ/abcdefghijklmnopqrstuvwxyz/' > ${NAMESLIST}
