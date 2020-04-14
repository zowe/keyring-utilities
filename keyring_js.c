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
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <gskcms.h>
#include <_Nascii.h>

#define NAPI_VERSION 5
#include <node_api.h>

#include "keyring_get.h"

#define MSG_BUF_LEN 256
#define NUM_ARG 4
#define MAX_FORMAT_LEN 3

int validateAndExtractString(napi_env, char*, napi_value, int, char*);
int encode_base64_and_create_napi_string(napi_env, char *, int , napi_value *);

napi_value GetData(napi_env env, napi_callback_info info) {
  napi_status status;
  napi_value args[NUM_ARG], dataobj, buffer_cert, buffer_key;
  void *underlying_buf_key, *underlying_buf_cert;

  char userid[MAX_USERID_LEN + 1];
  char keyring[MAX_KEYRING_LEN + 1];
  char label[MAX_LABEL_LEN + 1];
  char format[MAX_FORMAT_LEN + 1];


  size_t argc = NUM_ARG;
  status = napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  assert(status == napi_ok);

  if (argc != NUM_ARG) {
    napi_throw_type_error(env, NULL, 
      "Wrong number of arguments. Specify NUM_ARG string arguments: \"userid\", \"keyring\", \"label\", \"format (der|pem)\"");
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
    char err_msg[256];
    memset(err_msg,0,256);
    sprintf(err_msg, "R_datalib call failed: function code: %.2X, SAF rc: %d, RACF rc: %d, RACF rsn: %d\n", 
        ret_codes.function_code, ret_codes.SAF_return_code, ret_codes.RACF_return_code, ret_codes.RACF_reason_code);
    napi_throw_type_error(env, NULL, err_msg);
    return NULL;
  }

  if ( ! strcasecmp(format, "der")) {
    status = napi_create_arraybuffer(env, buffers.certificate_length, &underlying_buf_cert, &buffer_cert);
    assert(status == napi_ok);
    memcpy(underlying_buf_cert, buffers.certificate, buffers.certificate_length);

    status = napi_create_arraybuffer(env, buffers.private_key_length, &underlying_buf_key, &buffer_key);
    assert(status == napi_ok);
    memcpy(underlying_buf_key, buffers.private_key, buffers.private_key_length);
  } 
  else if ( ! strcasecmp(format, "b64")) {
    if (encode_base64_and_create_napi_string(env, buffers.certificate, buffers.certificate_length, &buffer_cert)) {
      return NULL;
    }
    if (encode_base64_and_create_napi_string(env, buffers.private_key, buffers.private_key_length, &buffer_key)) {
      return NULL;
    }
  } else {
    napi_throw_type_error(env, NULL, "Specified format is not supported.");
    return NULL;
  }

  status = napi_create_object(env, &dataobj);
  assert(status == napi_ok);

  status = napi_set_named_property(env, dataobj, "certificate", buffer_cert);
  assert(status == napi_ok);

  status = napi_set_named_property(env, dataobj, "key", buffer_key);
  assert(status == napi_ok);
  
  return dataobj;
}

int encode_base64_and_create_napi_string(napi_env env, char *buffer, int length, napi_value *value) {
  napi_status status;
  gsk_buffer buf_in = {length, buffer};
  gsk_buffer buf_out = {0, 0};
  gsk_status rc;
  if (gsk_encode_base64(&buf_in, &buf_out)) {
    napi_throw_type_error(env, NULL, "The gsk_encode_base64 function failed.");
    return 1;
  }
  __e2a_l(buf_out.data,buf_out.length);
  status = napi_create_string_latin1(env, buf_out.data, buf_out.length, value);
  assert(status == napi_ok);
  gsk_free_buffer(&buf_out);

  return 0;
}

int validateAndExtractString(napi_env env, char *dest, napi_value src, int length, char *location) {
  napi_valuetype valuetype;
  napi_status status; 
  size_t src_len, num_copied;

  memset(dest, 0, length + 1);

  status = napi_typeof(env, src, &valuetype);
  assert(status == napi_ok);
  
  if (valuetype != napi_string) {
    char msg[MSG_BUF_LEN];
    memset(msg, 0, MSG_BUF_LEN);
    sprintf(msg, "%s parameter has wrong argument type", location);
    napi_throw_type_error(env, NULL, msg);
    return 1;
  }
  status = napi_get_value_string_latin1(env, src, NULL, 0, &src_len);
  assert(status == napi_ok);
  
  if (src_len > length) {
    char msg[MSG_BUF_LEN];
    memset(msg, 0, MSG_BUF_LEN);
    sprintf(msg, "%s parameter is too long. Parameter can be up to %d bytes long", location, length);
    napi_throw_type_error(env, NULL, msg);
    return 1;
  }

  status = napi_get_value_string_latin1(env, src, dest, length + 1, &src_len);
  assert(status == napi_ok);

  return 0;
}

#define DECLARE_NAPI_METHOD(name, func)                                        \
  { name, 0, func, 0, 0, 0, napi_default, 0 }

napi_value Init(napi_env env, napi_value exports) {
  napi_status status;
  napi_property_descriptor desc = DECLARE_NAPI_METHOD("getData", GetData);
  status = napi_define_properties(env, exports, 1, &desc);
  assert(status == napi_ok);
  return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
