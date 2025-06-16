BASEDIR=$(dirname $0)
xlclang -q64 "-Wc,lp64,langlv(extc99),arch(10),TARGET(zOSV2R4)" -fPIE -Wl,lp64 -I${BASEDIR}/../src/h -o ${BASEDIR}/keyring-util \
    ${BASEDIR}/../src/c/keyring_util.c \
    ${BASEDIR}/../src/c/keyring_service.c \
    /usr/lib/GSKCMS64.x

#xlc -q64 -qarch=8 -I${BASEDIR}/../src/h -o ${BASEDIR}/keyring-util \
#                        ${BASEDIR}/../src/c/keyring_util.c \
#                        ${BASEDIR}/../src/c/keyring_get.c \
#                        ${BASEDIR}/../src/c/keyring_service.c \
#                        /usr/lib/GSKCMS64.x

rm *.o
