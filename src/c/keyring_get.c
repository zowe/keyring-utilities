/*
* This program and the accompanying materials are made available under the terms of the *
* Eclipse Public License v2.0 which accompanies this distribution, and is available at *
* https://www.eclipse.org/legal/epl-v20.html                                      *
*                                                                                 *
* SPDX-License-Identifier: EPL-2.0                                                *
*                                                                                 *
* Copyright Contributors to the Zowe Project.                                     *
*/

#include <string.h>
#include <stdlib.h>
#include "keyring_get.h"

void get_data(char *userid, char *keyring, char *label, Data_get_buffers *buffers, Return_codes *ret, int debug) {

    gsk_handle handle;
    int num_records;
    int rc = 0;
    gsk_buffer stream;
    gsk_buffer key_stream;
    // create a new string concatenating userid, keyring
    char concat_userid_keyring[MAX_EXTRA_ARG_LEN];
    strcat(strcat(strcpy(concat_userid_keyring, userid), "/"), keyring);
    printf("concat_userid_keyring: %s\n", concat_userid_keyring);
    // if the keyring is open successfully, search for the specified label
    rc = gsk_open_keyring(concat_userid_keyring, &handle, &num_records);

    if (rc != 0) {
        printf("Could not open keyring %s: rc = %X\n", concat_userid_keyring, rc);
        exit(1);
    }

    if (debug) {
        printf("gsk_open_keyring returned %d, num_records %d\n", rc, num_records);

    }

    rc = gsk_export_certificate(handle, label, gskdb_export_der_binary, &stream);

    if (rc == 0) {
        memcpy(&buffers->certificate_length, &stream.length, sizeof(stream.length));
        memcpy(buffers->certificate, stream.data, stream.length);
    } else {
        printf("Could not find certificate %s: GSK rc = %X\n", label, rc);
        exit(1);
    }
    if (debug) {
        printf("gsk_export_certificate returned %d, size=%d, ptr=%s\n", rc, stream.length, stream.data);
    }
    gsk_free_buffer(&stream);

    rc = gsk_export_key(handle, label, gskdb_export_pkcs12v3_binary, x509_alg_pbeWithSha1And128BitRc4, "password", &key_stream);

    if (rc == 0) {
        memcpy(&buffers->private_key_length, &key_stream.length, sizeof(key_stream.length));
        memcpy(buffers->private_key, key_stream.data, key_stream.length);
    } // not all certs have the private key attached, don't fail if it's not there

    if (debug) {
        printf("gsk_export_key returned %d, size=%d, ptr=%s\n", rc, key_stream.length, key_stream.data);
    }
    
    gsk_free_buffer(&key_stream);
    gsk_close_database(&handle);
}