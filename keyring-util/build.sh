xlc -q64 -qarch=8 -I../src/h -o keyring-util \
                        ../src/c/keyring_util.c \
                        ../src/c/keyring_get.c \
                        ../src/c/keyring_service.c \
                        /usr/lib/GSKCMS64.x

rm *.o