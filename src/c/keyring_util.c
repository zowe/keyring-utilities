/*
* This program and the accompanying materials are made available under the terms of the *
* Eclipse Public License v2.0 which accompanies this distribution, and is available at *
* https://www.eclipse.org/legal/epl-v20.html                                      *
*                                                                                 *
* SPDX-License-Identifier: EPL-2.0                                                *
*                                                                                 *
* Copyright Contributors to the Zowe Project.                                     *
*/

#define  _XOPEN_SOURCE_EXTENDED 1

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <gskcms.h>

#include "keyring_types.h"

#define CERTIFICATE_HEADER "-----BEGIN CERTIFICATE-----\n"
#define CERTIFICATE_FOOTER "-----END CERTIFICATE-----\n"
#define PRIVATE_HEADER "-----BEGIN PRIVATE KEY-----\n"
#define PRIVATE_FOOTER "-----END PRIVATE KEY-----\n"

// set by env or command line argument
int debug = 0;

int main(int argc, char **argv)
{
    int i;
    R_datalib_parm_list_64 p;
    Command_line_parms parms;
    if (getenv("KEYRING_UTIL_DEBUG") != NULL && ! strcmp(getenv("KEYRING_UTIL_DEBUG"), "YES")) {
        debug = 1;
    }
    memset(&parms, 0, sizeof(Command_line_parms));

    validate_and_set_parm(parms.function, argv[1], MAX_FUNCTION_LEN);
    if (strlen(parms.function) == 0) {
        print_help(NULL, NULL, NULL);
    }

    R_datalib_function function_table[] = {
        {"NEWRING", 2, NEWRING_CODE, 0x00000000, 0, NULL, simple_action},
        {"DELCERT", 2, DELCERT_CODE, 0x00000000, 0, NULL, delcert_action},
        {"DELRING", 2, DELRING_CODE, 0x00000000, 0, NULL, simple_action},
        {"REFRESH", 2, REFRESH_CODE, 0x00000000, 0, NULL, simple_action},
        {"EXPORT",  2, GETCERT_CODE, 0x80000000, 0, NULL, getcert_action},
        {"IMPORT",  2, IMPORT_CODE,  0x00000000, 0, NULL, import_action},
        {"HELP",    0, HELP_CODE,    0x00000000, 0, NULL, print_help},
        {"NOTSUPPORTED", 0, NOTSUPPORTED_CODE, 0x00000000, 0, NULL, print_help},
        {"LISTRING", 2, LISTRING_CODE, 0x00000000, 0, NULL, listring_action},
    };

    R_datalib_function r_function;
    for (i = 0; i < sizeof(function_table)/sizeof(R_datalib_function); i++) {
        if (strncasecmp(function_table[i].name, parms.function, sizeof(parms.function)) == 0) {
            r_function = function_table[i];
            break;
        }
        r_function = function_table[sizeof(function_table)/sizeof(R_datalib_function) - 1];
    }

    if (r_function.num_args == 0) {
        process_cmdline_parms(&parms, argc-2, &argv[2]);
    } else if (r_function.num_args == 2) {
        validate_and_set_parm(parms.userid, argv[2], MAX_USERID_LEN);
        validate_and_set_parm(parms.keyring, argv[3], MAX_KEYRING_LEN);
        if (strlen(parms.userid) == 0 || strlen(parms.keyring) == 0) {
            printf("Missing userid or keyring.\n");
            exit(1);
        }
        process_cmdline_parms(&parms, argc-4, &argv[4]);
    } else {
        printf("Unsupported number of args for %s\n", r_function.name);
        exit(1);
    }

    //print parms for debug
    if (debug) {
        printf(
            "Parms parsed: name: %s, userid: %s, keyring: %s, label: %s, usage:%s, userid: %s, print_label_only: %d, print_owner_only: %d, file_path: %s, file_password: %s, debug: %d\n", 
            parms.function, parms.userid, parms.keyring, parms.label, parms.usage, parms.userid, parms.print_label_only, parms.print_owner_only, parms.file_path, parms.file_password, debug  // ^^ added comma and formatted for readability ^^
        );
    }

    if (debug) {
        printf("Selected function is %s with code of %.2X\n", r_function.name, r_function.code);
    }
    r_function.action(&p, &r_function, &parms);

    return 0;
}

void get_data(char *userid, char *keyring, char *label, char* optional_password, Data_get_buffers *buffers, Return_codes *ret) {

    gsk_handle handle;
    int num_records;
    int rc = 0;
    gsk_buffer stream;
    gsk_buffer key_stream;
    // create a new string concatenating userid, keyring
    char concat_userid_keyring[MAX_EXTRA_ARG_LEN];
    strcat(strcat(strcpy(concat_userid_keyring, userid), "/"), keyring);
    if (debug) {
        printf("Opening keyring: %s\n", concat_userid_keyring);
    }
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
        memcpy(buffers->label, label, strlen(label));
    } else {
        printf("Could not find certificate %s: GSK rc = %X\n", label, rc);
        exit(1);
    }
    if (debug) {
        printf("gsk_export_certificate returned %d, size=%d\n", rc, stream.length);
    }
    gsk_free_buffer(&stream);

    char* pass= "password";
    if (optional_password!= NULL && strlen(optional_password) > 0) {
        pass = optional_password;
    }
    rc = gsk_export_key(handle, label, gskdb_export_pkcs12v3_binary, x509_alg_pbeWithSha1And128BitRc4, pass, &key_stream);

    if (rc == 0) {
        memcpy(&buffers->private_key_length, &key_stream.length, sizeof(key_stream.length));
        memcpy(buffers->private_key, key_stream.data, key_stream.length);
    } // not all certs have the private key attached, don't fail if it's not there

    if (debug) {
        printf("gsk_export_key returned %d, size=%d\n", rc, key_stream.length);
    }    
    
    gsk_free_buffer(&key_stream);
    gsk_close_database(&handle);
}

void resetGetParm(R_datalib_data_get *getParm) {
    getParm->certificate_len = MAX_CERTIFICATE_LEN;
    getParm->private_key_len = MAX_PRIVATE_KEY_LEN;
    getParm->label_len = MAX_LABEL_LEN;
    getParm->subjects_DN_length = MAX_SUBJECT_DN_LEN;
    getParm->record_ID_length = MAX_RECORD_ID_LEN;
    getParm->cert_userid_len = 0x08;
}
  

void printRdatalibException(int function, int safRC, int racfRC, int racfRSN ) {
    printf("R_datalib call failed: function code: %.2X, SAF rc: %d, RACF rc: %d, RACF rsn: %d\n",
        function, safRC, racfRC, racfRSN);
}

void import_action(R_datalib_parm_list_64* rdatalib_parms, void * function, Command_line_parms* parms) {   
    gsk_status rc;
    gsk_buffer buff_in, priv_key_buff, cert_buff;
    pkcs_cert_key cert_key;
    pkcs_certificates CAs;

    char label[MAX_LABEL_LEN + 1];
    memset(label, 0, MAX_LABEL_LEN + 1);

    R_datalib_data_put put_parm;
    memset(&put_parm, 0x00, sizeof(R_datalib_data_put));
    R_datalib_function *func = function;
    func->parmlist = &put_parm;

    // exit if parms is missing or has an empty label, file_path, file_password, or usage
    if (strlen(parms->label) == 0) {
        printf("Error: Certificate label is required for this action.\n");
        exit(1);
    } else if (strlen(parms->file_path) == 0 ) {
        printf("Missing required -f argument\n");
        exit(1);
    } else if (strlen(parms->file_password) == 0) {
        printf("Missing required -p argument\n");
        exit(1);
    } else if(strlen(parms->usage) == 0) {
        printf("Missing required -u argument\n");
        exit(1);
    }

    // parse and validate label
    if (strlen(parms->label) >= MAX_LABEL_LEN) {
        printf("Label too long, max length is %d\n", MAX_LABEL_LEN);
        exit(1);
    }

    // parse and validate usage
    printf("file path: %s\n", parms->file_path);
    if (load_pkcs12_file(&buff_in, /* pkcs12 file name */parms->file_path)) {
        return;
    }

    if ((rc = gsk_decode_import_key(&buff_in, /* pkcs12 password */parms->file_password, &cert_key, &CAs)) != 0) {
        printf("Could not read p12 file: rc = %X\n", rc);
        return;
    }

    printf("Private key content: \n%s\n%d\n", (char*)cert_key.privateKey.privateKey.data, cert_key.privateKey.privateKey.length);
    printf("Cert content: \n%s\n%d\n", (char*)cert_key.certificate.u.certificate.derCertificate.data, cert_key.certificate.u.certificate.derCertificate.length);

    if ((rc = gsk_encode_private_key(&cert_key.privateKey, &priv_key_buff)) != 0) {
        printf("WARN: Could not encode priv key: rc = %X. If you expected to import a private key, check your p12 file and ensure it's present.\n", rc);
    }

    if ((rc = gsk_encode_export_certificate(&cert_key.certificate, &CAs, gskdb_export_der_binary, &cert_buff)) != 0) {
        printf("Could not encode certificate: rc = %X\n", rc);
        return;
    }

    strcpy(label,parms->label);

    if (strcasecmp(parms->usage,"PERSONAL") == 0) {
        put_parm.certificate_usage = 0x00000008;
    } else if (strcasecmp(parms->usage,"CERTAUTH") == 0) {
        put_parm.certificate_usage = 0x00000002;
    } else {
        printf("ERROR: '%s' parameter is invalid. Use CERTAUTH or PERSONAL.\n", parms->usage);
        exit(1);
    }

    put_parm.Default = 0x00000000;
    put_parm.certificate_len = cert_buff.length;
    put_parm.certificate_ptr = cert_buff.data;
    put_parm.private_key_len = priv_key_buff.length;
    put_parm.private_key_ptr = priv_key_buff.data;
    put_parm.label_len = strlen(label);
    put_parm.label_ptr = label;
    put_parm.cert_userid_len = strlen(parms->userid);
    memset(put_parm.cert_userid, ' ', MAX_USERID_LEN); // fill the cert_userid field with blanks
    memcpy(put_parm.cert_userid, parms->userid, put_parm.cert_userid_len);

    set_up_R_datalib_parameters(rdatalib_parms, func, parms->userid, parms->keyring);
    invoke_R_datalib(rdatalib_parms);
    check_return_code(rdatalib_parms);

    // TODO automatic refresh if needed??? 

    gsk_free_buffer(&buff_in);
    gsk_free_buffer(&priv_key_buff);
    gsk_free_buffer(&cert_buff);
    gsk_free_certificates(&CAs);
    gsk_free_private_key_info(&cert_key.privateKey);
}

int load_pkcs12_file(gsk_buffer *buff_in, char *filename) {
    FILE *stream;
    int numread;
    struct stat info;
    char *buffer;

    if ((stream = fopen(filename, "r")) == NULL) {
        perror("Could not open provided pkcs12 file.");
        return 1;
    }
    
    if (stat(filename, &info) != 0) {
        perror("stat() error");
        return 1;
    } 

    if (S_ISREG(info.st_mode) == 0) {
        printf("The file is not a regular file\n");
        return 1;
    }

    buffer = (char *) malloc(info.st_size);

    numread = fread(buffer, sizeof(char), info.st_size, stream);

    if (numread != info.st_size) {
        if ( ferror(stream) ) {
            printf( "ERROR: Error reading pkcs12 file\n" );
            return 1;
        }
        else if ( feof(stream)) {     
            printf( "EOF found\n" );
            printf( "Number of characters read %d\n", numread );
        }
    }

    buff_in->data = buffer;
    buff_in->length = numread;

    if (fclose(stream)) {
        printf("fclose error.\n");
    }

    return 0;
}


int lengthWithoutTralingSpaces(char *str, int maxlen) {
    char *end = str + maxlen - 1;
    while (end >= str && *end == 0x40) end--;
    return end - str + 1;
  }
  

void addCertItem(Certificate_summary *summary, R_datalib_data_get *getParm, int index) {
    char *str;
    int certUserLen;
  
    certUserLen = lengthWithoutTralingSpaces(getParm->cert_userid, 8);
  
    strncpy(summary->label, getParm->label_ptr, getParm->label_len);
    strncpy(summary->userid, getParm->cert_userid, getParm->cert_userid_len);
  
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
    strncpy(summary->usage, str, strlen(str));
  
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
   
    strncpy(summary->status, str, strlen(str));
    summary->isDefault = getParm->Default;

    if (debug) {
        printf("%d: %s (%s) %s (%s)\n", index, summary->label, summary->userid, summary->usage, summary->status);
    }
    // if you want pem: getParm->certificate_ptr, getParm->certificate_len
  }

void list_certificate_summary(Certificate_summary *summary, Command_line_parms* params) {

    int print_this_cert = 1;
    if (strlen(params->label) > 0 && strcmp(summary->label, params->label) != 0) {
        print_this_cert = 0;
    }
    if (strlen(params->usage) > 0 && strcmp(summary->usage, params->usage) != 0) {
        print_this_cert = 0;
    }
    if (print_this_cert) {
        if (params->print_label_only) {
            printf("Certificate: %s\n", summary->label); 
        } else if (params->print_owner_only) {
            printf("Owner: %s\n", summary->userid);
        } else {
            printf("Certificate: %s\n", summary->label); 
            printf("Owner: %s\n", summary->userid);
            printf("Usage: %s\n", summary->usage);
            printf("Status: %s\n", summary->status);
            printf("Default: %s\n", summary->isDefault ? "YES" : "NO");
        }
    }
}

void listring_action(R_datalib_parm_list_64* rdatalib_parms, void * function, Command_line_parms* params) {
    int origMode;
    int rc = 0;
    char* userid = params->userid;
    char* keyring = params->keyring;
    Certificate_summary* summary_list[500];
    Data_get_buffers buffers;
    R_datalib_parm_list_64 parms;
    R_datalib_data_get getParm;
    R_datalib_result_handle handle;
    R_datalib_data_abort dataAbort;
  
    R_datalib_function getFirstFunc = {"", 0, GETCERT_CODE, 0x80000000, 1, &getParm, NULL};
    R_datalib_function getNextFunc = {"", 0, GETNEXT_CODE, 0x80000000, 1, &getParm, NULL};
    R_datalib_function abortFunc = {"", 0, DATA_ABORT_CODE, 0x00000000, 0, &dataAbort, NULL};
  
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
  
    resetGetParm(&getParm);
    set_up_R_datalib_parameters(&parms, &getFirstFunc, userid, keyring);
    invoke_R_datalib(&parms);
  
    if (parms.return_code != 0) {
      printRdatalibException(parms.function_code, parms.return_code, parms.RACF_return_code, parms.RACF_reason_code);
      exit(1);
    }
  
    summary_list[0] = malloc(sizeof(Certificate_summary));
    addCertItem(summary_list[0], &getParm, 0);
  
    int i = 1;
    while (1) {
      if (i == 500) {
        printf("Warning: More than 500 certificates found in the keyring. Only the first 500 are processed.\n");
        break;
      }
  
      resetGetParm(&getParm);
      set_up_R_datalib_parameters(&parms, &getNextFunc, userid, keyring);
      invoke_R_datalib(&parms);
  
      if (parms.return_code == 8 && parms.RACF_return_code == 8 && parms.RACF_reason_code == 44) { // No more cert found;
        break;
      }
      else if (parms.return_code != 0) {
        printRdatalibException(parms.function_code, parms.return_code, parms.RACF_return_code, parms.RACF_reason_code);
        rc = parms.return_code;
        // cleanup allocations before exiting
        for (int j = 0; j < i; j++) {
            free(summary_list[j]);
        }
        exit(1);
      }
      else {
        summary_list[i] = malloc(sizeof(Certificate_summary));
        addCertItem(summary_list[i], &getParm, i);
        i++;
      }
    }

    dataAbort.handle = &handle;
    set_up_R_datalib_parameters(&parms, &abortFunc, userid, keyring);
    invoke_R_datalib(&parms);
    printf("Summary of certificates:\n");
    for (int j = 0; j < i; j++) {
        list_certificate_summary(summary_list[j], params);
        free(summary_list[j]);
    }
    return;
}

void getcert_action(R_datalib_parm_list_64* rdatalib_parms, void * function, Command_line_parms* parms) {
    R_datalib_function *func = function;


    if (strlen(parms->label) == 0) {
        printf("Error: Certificate label is required for this action.\n");
        exit(1);
    }
    if (debug) {
        printf("%s action\n", func->name);
    }
    Data_get_buffers buffers;
    Return_codes ret_codes;
    memset(&ret_codes, 0, sizeof(Return_codes));
    memset(&buffers, 0, sizeof(Data_get_buffers));

    get_data(parms->userid, parms->keyring, parms->label, parms->file_password, &buffers, &ret_codes);

    if (ret_codes.SAF_return_code != 0) {
        printf("R_datalib call failed: function code: %.2X, SAF rc: %d, RACF rc: %d, RACF rsn: %d\n",
            ret_codes.function_code, ret_codes.SAF_return_code, ret_codes.RACF_return_code, ret_codes.RACF_reason_code);
        return;
    }
    dump_certificate_and_key(&buffers, parms);
}

void simple_action(R_datalib_parm_list_64* rdatalib_parms, void * function, Command_line_parms* parms) {
    R_datalib_function *func = function;
    if (debug) {
        printf("%s action\n", func->name);
    }
    set_up_R_datalib_parameters(rdatalib_parms, function, parms->userid, parms->keyring);
    invoke_R_datalib(rdatalib_parms);
    check_return_code(rdatalib_parms);
}

void delcert_action(R_datalib_parm_list_64* rdatalib_parms, void * function, Command_line_parms* parms) {
    R_datalib_function *func = function;

    R_datalib_data_remove rem_parm;
    memset(&rem_parm, 0x00, sizeof(R_datalib_data_remove));

    func->parmlist = &rem_parm;

    if (debug) {
        printf("%s action\n", func->name);
    }

    if(strlen(parms->label) == 0) {
        printf("Error: Certificate label is required for this action.\n");
        exit(1);
    }

    rem_parm.label_len = strlen(parms->label);
    rem_parm.label_addr = parms->label;
    rem_parm.CERT_userid_len = strlen(parms->userid);
    memset(rem_parm.CERT_userid, ' ', MAX_USERID_LEN); // fill the CERT_userid field with blanks
    memcpy(rem_parm.CERT_userid, parms->userid, rem_parm.CERT_userid_len);

    set_up_R_datalib_parameters(rdatalib_parms, func, parms->userid, parms->keyring);
    invoke_R_datalib(rdatalib_parms);
    check_return_code(rdatalib_parms);
    // refresh DIGTCERT class if required
    if (rdatalib_parms->return_code == 4 && rdatalib_parms->RACF_return_code == 4 && rdatalib_parms->RACF_reason_code == 12) {
        printf("DIGTCERT class has to refreshed.\n");
        func->code = REFRESH_CODE;
        set_up_R_datalib_parameters(rdatalib_parms, func, "", "");
        invoke_R_datalib(rdatalib_parms);
        check_return_code(rdatalib_parms);
        printf("DIGTCERT class refreshed.\n");
    }
}

void dump_certificate_and_key(Data_get_buffers *buffers, Command_line_parms* parms) {
    char filename[40];
    memset(filename, 0, strlen(filename));

    if (strlen(parms->file_path) > 0) {
        strcpy(filename, parms->file_path);
    } else {
        strcpy(filename, buffers->label);
        strcat(filename, parms->export_key ? ".p12" : ".pem");
    }

    if (parms->export_key) {    
        write_to_file(filename, buffers->private_key, buffers->private_key_length, TRUE);
    } else {
        write_to_file(filename, buffers->certificate, buffers->certificate_length, FALSE);
    }
}

void write_to_file(char *filename, char *ptr, int len, int isPrivate) {

    FILE *stream;
    int numwritten;
    gsk_buffer buf_in = {len, ptr};
    gsk_buffer buf_out = {0, 0};
    gsk_status rc;

    if (isPrivate) {
        if ((stream = fopen(filename, "wb")) == NULL) {
            printf("Could not open %s file.\n", filename);
            return;
        }
        numwritten = fwrite(buf_in.data, sizeof(char), buf_in.length, stream);

    } else {
        rc = gsk_encode_base64(&buf_in, &buf_out);
        if (debug) printf("gsk_encode_base64 rc=%d\n", rc);
    
        if ((stream = fopen(filename, "w")) == NULL) {
            printf("Could not open %s file.\n", filename);
            return;
        }
    
        fprintf(stream, CERTIFICATE_HEADER);
        numwritten = fwrite(buf_out.data, sizeof(char), buf_out.length, stream);
        fprintf(stream, CERTIFICATE_FOOTER);
    }

    

    gsk_free_buffer(&buf_out);

    if (debug)
        printf("Number of characters written to %s file is %d\n", filename, numwritten);

    if (fclose(stream)) {
        printf("fclose error.\n");
    }
}

void validate_and_set_parm(char * parm, char * cmd_parm, int maxlen) {
    if (strlen(cmd_parm) <= maxlen) {
        strcpy(parm, cmd_parm);
    } else {
        printf("ERROR: %s parm too long and will not be set.\n", cmd_parm);
    }
}

void check_return_code(R_datalib_parm_list_64* p) {
    if (p->return_code != 0 || p->RACF_return_code != 0 || p->RACF_reason_code != 0) {
        printf("Function code: %.2X, SAF rc: %d, RACF rc: %d, RACF rsn: %d\n",
            p->function_code, p->return_code, p->RACF_return_code, p->RACF_reason_code);
    }
}

void require_option_value(char *optionName, char *optionValue) {
    if (optionValue == NULL || strlen(optionValue) == 0) { 
        printf("ERROR: Option %s requires a value.\n", optionName);
        exit(1);
    }
}

void process_cmdline_parms(Command_line_parms* parms, int argc, char** argv) {
    int argx = 0;
    while( argx < argc) {
        char *optionValue = NULL;
        if (strcmp(argv[argx], "-v") == 0) {
            debug = 1;
        } else if (strcmp(argv[argx], "-l") == 0) {
            optionValue = argv[++argx];
            require_option_value("-l", optionValue);
            validate_and_set_parm(parms->label, optionValue, MAX_LABEL_LEN);
        } else if (strcmp(argv[argx], "-u") == 0) {
            optionValue = argv[++argx];
            require_option_value("-u", optionValue);
            validate_and_set_parm(parms->usage, optionValue, MAX_USAGE_LEN);
        } else if (strcmp(argv[argx], "-f") == 0) {
            optionValue = argv[++argx];
            require_option_value("-f", optionValue);
            validate_and_set_parm(parms->file_path, optionValue, MAX_EXTRA_ARG_LEN);
        } else if (strcmp(argv[argx], "-p") == 0) {
            optionValue = argv[++argx];
            require_option_value("-p", optionValue);
            validate_and_set_parm(parms->file_password, optionValue, MAX_EXTRA_ARG_LEN);
        } else if (strcmp(argv[argx], "--label-only") == 0) {
            parms->print_label_only = 1;
        } else if (strcmp(argv[argx], "-k") == 0) {
            parms->export_key = 1;
        } else if (strcmp(argv[argx], "--owner-only") == 0) {
            parms->print_owner_only = 1;
        } else if (strcmp(argv[argx], "--help") == 0) {
            print_help(NULL, NULL, NULL);
            exit(0);
        }else {
            printf("ERROR: Unknown option: %s\n", argv[argx]);
            exit(1);
        }
        argx++;
    }
}

void print_help(R_datalib_parm_list_64* rdatalib_parms, void * function, Command_line_parms* parms) {
    printf("----------------------------------------------------\n");
    printf("Usage: keyring-util function <userid> <keyring> <args>\n");
    printf("----------------------------------------------------\n");
    printf("common args:\n");
    printf("'-v'     Sets verbose logging\n");
    printf("function:\n");
    printf("LISTRING - lists certificates in a keyring. args: -l <labelFilter>, -u <usageFilter>, --label-only, --usage-only.\n");
    printf("NEWRING - creates a new keyring. args: none\n");
    printf("DELRING - deletes a keyring. args: none\n");
    printf("DELCERT - disconnects a certificate (label) from a keyring or deletes a certificate from RACF database. args: -l <label>\n");
    printf("EXPORT  - exports a certificate from a keyring to a PEM file. args: -l <label>. optional: -k, -f <path/to/file/out> -p <password>\n");
    printf("IMPORT  - imports a certificate (with a private key if present) to a keyring from PKCS12 file. args: -l <label>, -f <path/to/pkcs12>, -p <pkcs12-password>\n");
    printf("REFRESH - refreshes DIGTCERT class\n");
    printf("HELP    - prints this help\n");
}

