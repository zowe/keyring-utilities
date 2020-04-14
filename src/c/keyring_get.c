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

#include "keyring_get.h"

void get_data(char *userid, char *keyring, char *label , Data_get_buffers *buffers, Return_codes *rc) {
    R_datalib_data_get get_parm;
    memset(&get_parm, 0x00, sizeof(R_datalib_data_get));
    R_datalib_result_handle handle;
    memset(&handle, 0x00, sizeof(R_datalib_result_handle));

    R_datalib_function function = {"", GETCERT_CODE, 0x80000000, 0, &get_parm, NULL};

    // Configure result handle. Request a certificate with a specific label

    handle.number_predicates = 1; 
    handle.attribute_id = 1; // Attribute data to match on is label
    handle.attribute_length = strlen(label);
    handle.attribute_ptr = label;

    get_parm.handle = &handle;
    get_parm.certificate_len = MAX_CERTIFICATE_LEN;
    get_parm.certificate_ptr = buffers->certificate;
    get_parm.private_key_len = MAX_PRIVATE_KEY_LEN;
    get_parm.private_key_ptr = buffers->private_key;
    get_parm.label_len = MAX_LABEL_LEN;
    get_parm.label_ptr = buffers->label;
    get_parm.cert_userid_len = 0x08;
    get_parm.subjects_DN_length = MAX_SUBJECT_DN_LEN;
    get_parm.subjects_DN_ptr = buffers->subject_DN;
    get_parm.record_ID_length = MAX_RECORD_ID_LEN;
    get_parm.record_ID_ptr = buffers->record_id;

    R_datalib_parm_list_64 rdatalib_parms;
   
    set_up_R_datalib_parameters(&rdatalib_parms, &function, userid, keyring);
    invoke_R_datalib(&rdatalib_parms);

    buffers->certificate_length = get_parm.certificate_len;
    buffers->label_length = get_parm.label_len;
    buffers-> private_key_length = get_parm.private_key_len;
    buffers->subject_DN_length = get_parm.subjects_DN_length;

    rc->function_code  = rdatalib_parms.function_code;
    rc->SAF_return_code = rdatalib_parms.return_code;
    rc->RACF_return_code = rdatalib_parms.RACF_return_code;
    rc->RACF_reason_code = rdatalib_parms.RACF_reason_code;

    // run Data abort to free up resources 
    R_datalib_data_abort data_abort;
    data_abort.handle = &handle;
    R_datalib_function abort_function;
    abort_function.code = DATA_ABORT_CODE;
    abort_function.default_attributes = 0;
    abort_function.parm_list_version = 0;
    abort_function.parmlist = &data_abort;
    abort_function.action = NULL;

    set_up_R_datalib_parameters(&rdatalib_parms, &abort_function, userid, keyring);
    invoke_R_datalib(&rdatalib_parms);

    return;
}

