BASEDIR=$(dirname $0)
c89 -W"c,lp64,langlv(STDC99),arch(8)" -Wl,lp64 -I${BASEDIR}/../src/h -o ${BASEDIR}/keyring-util \
    ${BASEDIR}/../src/c/keyring_util.c \
    ${BASEDIR}/../src/c/keyring_service.c \
    /usr/lib/GSKCMS64.x

#xlc -q64 -qarch=8 -I${BASEDIR}/../src/h -o ${BASEDIR}/keyring-util \
#                        ${BASEDIR}/../src/c/keyring_util.c \
#                        ${BASEDIR}/../src/c/keyring_get.c \
#                        ${BASEDIR}/../src/c/keyring_service.c \
#                        /usr/lib/GSKCMS64.x

rm *.o
