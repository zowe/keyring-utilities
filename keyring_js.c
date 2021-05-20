/*
* This program and the accompanying materials are made available under the terms of the *
* Eclipse Public License v2.0 which accompanies this distribution, and is available at *
* https://www.eclipse.org/legal/epl-v20.html                                      *
*                                                                                 *
* SPDX-License-Identifier: EPL-2.0                                                *
*                                                                                 *
* Copyright Contributors to the Zowe Project.                                     *
*/

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <gskcms.h>
#include <_Nascii.h>

#define NAPI_VERSION 5
#include <node_api.h>

#include "keyring_get.h"

#define MSG_BUF_LEN 256
#define GET_DATA_NUM_ARG 4
#define LIST_KEYRING_NUM_ARG 2
#define MAX_FORMAT_LEN 3

#define BEGINCERT "-----BEGIN CERTIFICATE-----\n"
#define ENDCERT "-----END CERTIFICATE-----"
#define BEGINPRIVKEY "-----BEGIN PRIVATE KEY-----\n"
#define ENDPRIVKEY "-----END PRIVATE KEY-----"


int validateAndExtractString(napi_env, char*, napi_value, int, char*);
int encode_base64_and_create_napi_string(napi_env, char *, int , napi_value *, char *, char *);

void throwRdatalibException(napi_env env, int function, int safRC, int racfRC, int racfRSN ) {
  char err_msg[256];
  memset(err_msg,0,256);
  sprintf(err_msg, "R_datalib call failed: function code: %.2X, SAF rc: %d, RACF rc: %d, RACF rsn: %d\n",
      function, safRC, racfRC, racfRSN);
  napi_throw_error(env, NULL, err_msg);
}

// Entry point to the getData() function
napi_value GetData(napi_env env, napi_callback_info info) {
  napi_status status;
  napi_value args[GET_DATA_NUM_ARG], dataobj, buffer_cert, buffer_key;
  void *underlying_buf_key, *underlying_buf_cert;

  char userid[MAX_USERID_LEN + 1];
  char keyring[MAX_KEYRING_LEN + 1];
  char label[MAX_LABEL_LEN + 1];
  char format[MAX_FORMAT_LEN + 1];


  size_t argc = GET_DATA_NUM_ARG;
  assert(napi_get_cb_info(env, info, &argc, args, NULL, NULL) == napi_ok);

  if (argc != GET_DATA_NUM_ARG) {
    napi_throw_type_error(env, NULL,
      "Wrong number of arguments. Specify GET_DATA_NUM_ARG string arguments: \"userid\", \"keyring\", \"label\", \"format (der|pem)\"");
    return NULL;
  }

  if (validateAndExtractString(env, userid, args[0], MAX_USERID_LEN, "First")) {
    return NULL;
  }
  if (validateAndExtractString(env, keyring, args[1], MAX_KEYRING_LEN, "Second")) {
    return NULL;
  }
  if (validateAndExtractString(env, label, args[2], MAX_LABEL_LEN, "Third")) {
    return NULL;
  }
    if (validateAndExtractString(env, format, args[3], MAX_FORMAT_LEN, "Fourth")) {
    return NULL;
  }

  __a2e_l(userid, MAX_USERID_LEN);
  __a2e_l(keyring, MAX_KEYRING_LEN);
  __a2e_l(label, MAX_LABEL_LEN);

  Data_get_buffers buffers;
  memset(&buffers, 0x00, sizeof(Data_get_buffers));
  Return_codes ret_codes;

  int orig_mode = __ae_thread_swapmode(__AE_EBCDIC_MODE);
  get_data(userid, keyring, label, &buffers, &ret_codes);
  __ae_thread_swapmode(orig_mode);
  if (ret_codes.SAF_return_code != 0) {
    throwRdatalibException(env, ret_codes.function_code, ret_codes.SAF_return_code,
                           ret_codes.RACF_return_code, ret_codes.RACF_reason_code);
    return NULL;
  }

  if ( ! strcasecmp(format, "der")) {
    assert(napi_create_arraybuffer(env, buffers.certificate_length, &underlying_buf_cert, &buffer_cert) == napi_ok);
    memcpy(underlying_buf_cert, buffers.certificate, buffers.certificate_length);

    assert(napi_create_arraybuffer(env, buffers.private_key_length, &underlying_buf_key, &buffer_key) == napi_ok);
    memcpy(underlying_buf_key, buffers.private_key, buffers.private_key_length);
  }
  else if ( ! strcasecmp(format, "pem")) {
    if (encode_base64_and_create_napi_string(env, buffers.certificate, buffers.certificate_length, &buffer_cert, BEGINCERT, ENDCERT)) {
      return NULL;
    }
    if (encode_base64_and_create_napi_string(env, buffers.private_key, buffers.private_key_length, &buffer_key, BEGINPRIVKEY, ENDPRIVKEY)) {
      return NULL;
    }
  } else {
    napi_throw_type_error(env, NULL, "Specified format is not supported.");
    return NULL;
  }

  assert(napi_create_object(env, &dataobj) == napi_ok);
  assert(napi_set_named_property(env, dataobj, "certificate", buffer_cert) == napi_ok);
  assert(napi_set_named_property(env, dataobj, "key", buffer_key) == napi_ok);

  return dataobj;
}

void resetGetParm(R_datalib_data_get *getParm) {
  getParm->certificate_len = MAX_CERTIFICATE_LEN;
  getParm->private_key_len = MAX_PRIVATE_KEY_LEN;
  getParm->label_len = MAX_LABEL_LEN;
  getParm->subjects_DN_length = MAX_SUBJECT_DN_LEN;
  getParm->record_ID_length = MAX_RECORD_ID_LEN;
  getParm->cert_userid_len = 0x08;
}

int lengthWithoutTralingSpaces(char *str, int maxlen) {
  char *end = str + maxlen - 1;
  while (end >= str && isspace((unsigned char)*end)) end--;
  return end - str + 1;
}

// Add an element with cert information to the nodejs array
void addCertItem(napi_env env, napi_value *array, R_datalib_data_get *getParm, int index) {
  napi_value element, string, isDefault;
  char *str;

  __e2a_l(getParm->label_ptr, getParm->label_len);
  __e2a_l(getParm->cert_userid, getParm->cert_userid_len);

  assert(napi_create_object(env, &element) == napi_ok);

  assert(napi_create_string_latin1(env, getParm->label_ptr, getParm->label_len, &string) == napi_ok);
  assert(napi_set_named_property(env, element, "label", string) == napi_ok);

  assert(napi_create_string_latin1(env, getParm->cert_userid, lengthWithoutTralingSpaces(getParm->cert_userid, 8), &string) == napi_ok);
  assert(napi_set_named_property(env, element, "owner", string) == napi_ok);

  switch (getParm->certificate_usage) {
    case 0x00000008:
      str = "PERSONAL";
      break;
    case 0x00000002:
      str = "CERTAUTH";
      break;
    default:
      str = "OTHER";
  }
  assert(napi_create_string_latin1(env, str, strlen(str), &string) == napi_ok);
  assert(napi_set_named_property(env, element, "usage", string) == napi_ok);

  switch (getParm->certificate_status) {
    case 0x80000000:
      str = "TRUST";
      break;
    case 0x40000000:
      str = "HIGHTRUST";
      break;
    case 0x20000000:
      str = "NOTRUST";
      break;
    default:
      str = "UNKNOWN";
  }
  assert(napi_create_string_latin1(env, str, strlen(str), &string) == napi_ok);
  assert(napi_set_named_property(env, element, "status", string) == napi_ok);

  if (getParm->Default == 0) {
    assert(napi_get_boolean(env, 0, &isDefault) == napi_ok);
  } else {
    assert(napi_get_boolean(env, 1, &isDefault) == napi_ok);
  }
  assert(napi_set_named_property(env, element, "default", isDefault) == napi_ok);

  encode_base64_and_create_napi_string(env, getParm->certificate_ptr, getParm->certificate_len, &string, BEGINCERT, ENDCERT);
  assert(napi_set_named_property(env, element, "pem", string) == napi_ok);

  assert(napi_set_element(env, *array, index, element) == napi_ok);

}

// Query keyring information using R_datalib API
int getKeyringContent(napi_env env, napi_value *array, char *userid, char *keyring) {
  int origMode;
  int rc = 0;
  napi_value element;
  Data_get_buffers buffers;
  R_datalib_parm_list_64 parms;
  R_datalib_data_get getParm;
  R_datalib_result_handle handle;
  R_datalib_data_abort dataAbort;

  R_datalib_function getFirstFunc = {"", GETCERT_CODE, 0x80000000, 1, &getParm, NULL};
  R_datalib_function getNextFunc = {"", GETNEXT_CODE, 0x80000000, 1, &getParm, NULL};
  R_datalib_function abortFunc = {"", DATA_ABORT_CODE, 0x00000000, 0, &dataAbort, NULL};

  memset(&buffers, 0x00, sizeof(Data_get_buffers));
  memset(&getParm, 0x00, sizeof(R_datalib_data_get));
  memset(&handle, 0x00, sizeof(R_datalib_result_handle));

  getParm.handle = &handle;
  getParm.certificate_ptr = buffers.certificate;
  getParm.private_key_ptr = buffers.private_key;
  getParm.label_ptr = buffers.label;
  getParm.subjects_DN_ptr = buffers.subject_DN;
  getParm.record_ID_ptr = buffers.record_id;
  // X'80000000' = TRUST; X'40000000' = HIGHTRUST; X'20000000' = NOTRUST; X'00000000' = ANY
  getParm.certificate_status = 0x00000000;

  __a2e_l(userid, MAX_USERID_LEN);
  __a2e_l(keyring, MAX_KEYRING_LEN);

  resetGetParm(&getParm);
  set_up_R_datalib_parameters(&parms, &getFirstFunc, userid, keyring);
  invoke_R_datalib(&parms);

  if (parms.return_code != 0) {
    throwRdatalibException(env, parms.function_code, parms.return_code, parms.RACF_return_code, parms.RACF_reason_code);
    return parms.return_code;
  }

  addCertItem(env, array, &getParm, 0);

  int i = 1;
  while (1) {

    resetGetParm(&getParm);
    set_up_R_datalib_parameters(&parms, &getNextFunc, userid, keyring);
    invoke_R_datalib(&parms);

    if (parms.return_code == 8 && parms.RACF_return_code == 8 && parms.RACF_reason_code == 44) { // No more cert found;
      break;
    }
    else if (parms.return_code != 0) {
      throwRdatalibException(env, parms.function_code, parms.return_code, parms.RACF_return_code, parms.RACF_reason_code);
      rc = parms.return_code;
      break;
    }
    else {
      addCertItem(env, array, &getParm, i++);
    }
  }

  dataAbort.handle = &handle;
  set_up_R_datalib_parameters(&parms, &abortFunc, userid, keyring);
  invoke_R_datalib(&parms);

  return rc;
}

// Entry point to the listKeyring() function
napi_value ListKeyring(napi_env env, napi_callback_info info) {
  napi_status status;
  napi_value args[LIST_KEYRING_NUM_ARG], array;

  char userid[MAX_USERID_LEN + 1];
  char keyring[MAX_KEYRING_LEN + 1];

  size_t argc = LIST_KEYRING_NUM_ARG;
  assert(napi_get_cb_info(env, info, &argc, args, NULL, NULL) == napi_ok);

  if (argc != LIST_KEYRING_NUM_ARG) {
    napi_throw_type_error(env, NULL,
      "Wrong number of arguments. Specify LIST_KEYRING_NUM_ARG string arguments: \"userid\", \"keyring\"");
    return NULL;
  }

  if (validateAndExtractString(env, userid, args[0], MAX_USERID_LEN, "First")) {
    return NULL;
  }
  if (validateAndExtractString(env, keyring, args[1], MAX_KEYRING_LEN, "Second")) {
    return NULL;
  }

  assert(napi_create_array(env, &array) == napi_ok);

  if (getKeyringContent(env, &array, userid, keyring) != 0) {
    return NULL;
  }

  return array;
}

int encode_base64_and_create_napi_string(napi_env env, char *buffer, int length, napi_value *value, char *header, char *footer) {
  napi_status status;
  gsk_buffer buf_in = {length, buffer};
  gsk_buffer buf_out = {0, 0};
  gsk_status rc;
  if (gsk_encode_base64(&buf_in, &buf_out)) {
    napi_throw_type_error(env, NULL, "The gsk_encode_base64 function failed.");
    return 1;
  }
  __e2a_l(buf_out.data,buf_out.length);

  char pem[buf_out.length + strlen(header) + strlen(footer)];
  memcpy(pem, header, strlen(header));
  memcpy((char *)pem + strlen(header), buf_out.data, buf_out.length);
  memcpy((char *)pem + strlen(header) + buf_out.length, footer, strlen(footer));

  assert(napi_create_string_latin1(env, pem, sizeof(pem), value) == napi_ok);
  gsk_free_buffer(&buf_out);

  return 0;
}

// Validate an input parameter and turn it into the C string
int validateAndExtractString(napi_env env, char *dest, napi_value src, int length, char *location) {
  napi_valuetype valuetype;
  napi_status status;
  size_t src_len, num_copied;

  memset(dest, 0, length + 1);

  assert(napi_typeof(env, src, &valuetype) == napi_ok);

  if (valuetype != napi_string) {
    char msg[MSG_BUF_LEN];
    memset(msg, 0, MSG_BUF_LEN);
    sprintf(msg, "%s parameter has wrong argument type", location);
    napi_throw_type_error(env, NULL, msg);
    return 1;
  }
  assert(napi_get_value_string_latin1(env, src, NULL, 0, &src_len) == napi_ok);

  if (src_len > length) {
    char msg[MSG_BUF_LEN];
    memset(msg, 0, MSG_BUF_LEN);
    sprintf(msg, "%s parameter is too long. Parameter can be up to %d bytes long", location, length);
    napi_throw_type_error(env, NULL, msg);
    return 1;
  }

  assert(napi_get_value_string_latin1(env, src, dest, length + 1, &src_len) == napi_ok);

  return 0;
}

#define DECLARE_NAPI_METHOD(name, func)                                        \
  { name, 0, func, 0, 0, 0, napi_default, 0 }

#define NUMBER_OF_FUNCTIONS 2

napi_value Init(napi_env env, napi_value exports) {
  napi_status status;
  napi_property_descriptor desc[NUMBER_OF_FUNCTIONS];

  desc[0] = (napi_property_descriptor) DECLARE_NAPI_METHOD("getData", GetData);
  desc[1] = (napi_property_descriptor) DECLARE_NAPI_METHOD("listKeyring", ListKeyring);

  assert(napi_define_properties(env, exports, NUMBER_OF_FUNCTIONS, desc) == napi_ok);

  return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
