# keyring-utilities
Various key ring utilities that interact with z/OS RACF key rings using R_datalib API and GSK APIs.

## keyring-util tool

The `keyring-util` tool is the primary artifact produced by this repository.

The keyring-util program leverages
[R_datalib callable service](https://www.ibm.com/docs/en/zos/2.5.0?topic=descriptions-r-datalib-irrsdl00-irrsdl64-certificate-data-library)
and [GSK CSM APIs](https://www.ibm.com/docs/en/zos/2.5.0?topic=programming-certificate-management-services-cms-api-reference) to perform various operations on digital certificates and RACF key rings. GSM CSM APIs are preferred when available, however, they don't always return complete metadata surrounding certificate definitions, which the R_datalib callable services will provide.

## Build
Enter the `build/` directory and execute the `build.sh` script

## Syntax
```bash
keyring-util function userid keyring label
```
**Parameters:**
 1. `function` see [Functions](#Functions) section below
 2. `userid` - an owner of the `keyring` and `label` certificate
 3. `keyring` - a name of the keyring
 4. **(Optional)** `-v`: verbose logging.
 5. Command-specific arguments, see [Functions](#Functions) Supported Arguments.

## Functions

  * `LISTRING` - lists keyring contents in a summarized format containing Label, Owner, Usage, Status, and Default.
    - Supported Arguments:
        * `-l <label>`: Optional. Limits output to certificates with an alias matching `label`.
        * `-u <usage>`: Optional. Limits output to certificates with USAGE matching `<usage>`. One of `CERTAUTH`, `PERSONAL`, `OTHER`.
        * `--label-only`: Optional. Limits output to the label field only. Higher priority than `--owner-only`.
        * `--owner-only`: Optional. Limits output to the owner field only.
    - Examples:
        * `keyring-util NEWRING USER01 RING02`
        * `keyring-util NEWRING USER01 RING02 -l SOMELBL`
        * `keyring-util NEWRING USER01 RING02 -u PERSONAL --label-only`

  * `NEWRING` - creates a keyring
    - Example: `keyring-util NEWRING USER01 RING02`

  * `DELRING` - deletes a keyring
       * Example: `keyring-util DELRING USER01 RING02`

  * `DELCERT` - remove a certificate from a keyring or deletes a certificate from RACF database
    - Supported Arguments:
        * `-l <label>`: Required. Specifies the certificate to be removed by label.
    **Current Limitation:** The `DELCERT` function can only manipulate a certificate that is owned by the `userid`, i.e. it can't
     work with certificates owned by the CERTAUTH, SITE or different userid.

    The following example removes `CERT03` certificate owned by the `USER01` from the `RING02` keyring owned by the `USER01` userid
    * Example: `keyring-util DELCERT USER01 RING02 -l CERT03`

    The following example removes `CERT03` certificate owned by the `USER01` from the RACF database. The command fails if the certificate
    is still connected to some keyring.
    * Example: `keyring-util DELCERT USER01 '*' -l CERT03`
       
  * `EXPORT` - exports a certificate in PEM format. The file is created in a `pwd` directory with a name of `<cert_alias>.pem`
    - Supported Arguments:
        * `-l <label>`: Required. Specifies the certificate to be exported by label.

    - Example: `keyring-util EXPORT USER01 RING02 -l CERT03`
        * Creates a file CERT03.pem.
         
  * `IMPORT` - imports a certificate from the PKCS12 format. The certificate can be connected to a keyring as `PERSONAL` or `CERTAUTH`.
    - Supported Arguments:
        * `-l <label>`: Required. Specifies the certificate label of the created keyring certificate.
        * `-u <usage>`: Required. One of `CERTAUTH`, `PERSONAL`.
        * `-f </path/to/p12/file>`: Required.  Specifies the path to the PKCS12 certificate being imported.
        * `-p <pkcs12-password>`: Required. Specifies the password required to open the PKCS12 certificate specified by `-f`.

    **Warning:** The scenario where a private key is also imported currently works only with RACF.
    * Example: `keyring-util IMPORT USER01 RING02 -l CERT03 -u PERSONAL -f /path/to/file.p12 -p pkcs12_password`
         
  * `REFRESH` - refreshes DIGTCERT class
    * Example: `keyring-util REFRESH`

For any return and reason codes, check [R_datalib return and reason codes](https://www.ibm.com/support/knowledgecenter/SSLTBW_2.4.0/com.ibm.zos.v2r4.ichd100/ich2d100238.htm)

## Further development
There is room for improvement:
  * command line argument processing and syntax (perhaps using the argp library from [ambitus project](https://github.com/ambitus/glibc/tree/zos/2.28/master/argp))
  * an extension of functionality of the current R_datalib functions
  * adding support for other [R_datalib functions](https://www.ibm.com/support/knowledgecenter/SSLTBW_2.4.0/com.ibm.zos.v2r4.ichd100/ich2d100226.htm)

Work with the following resource if you want to add support for other R_datalib functions [Data areas for R_datalib callable service](https://www.ibm.com/support/knowledgecenter/SSLTBW_2.4.0/com.ibm.zos.v2r4.ichc400/comx.htm)


