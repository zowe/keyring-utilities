/*
* This program and the accompanying materials are made available under the terms of the *
* Eclipse Public License v2.0 which accompanies this distribution, and is available at *
* https://www.eclipse.org/legal/epl-v20.html                                      *
*                                                                                 *
* SPDX-License-Identifier: EPL-2.0                                                *
*                                                                                 *
* Copyright Contributors to the Zowe Project.                                     *
*/

const keyring = require('./');
const https = require('https');
const os = require('os');


/*
 * Get keyring content.
 *
 * returns an array of objects representing certificates in a keyring:
 * 
 * [
 *   {
 *     label: 'cert_label',
 *     owner: 'CERTAUTH',
 *     usage: 'CERTAUTH',
 *     status: 'TRUST',
 *     default: false,
 *     pem: '-----BEGIN CERTIFICATE-----\n' +
 *         certificate content in base64
 *     '-----END CERTIFICATE-----'
 *   },
 *   ...
 * ]
 */
results = keyring.listKeyring("USERID", "Keyring");

console.log("Keyring content:")
let certificate;
for (const item of results) {
  console.log(item);
}


/*
 * Get CA chain of a certificate.
 *
 * returns an array of objects representing CA chain of the certificate in a keyring:
 * 
 * [
 *   {
 *     label: 'cert_label',
 *     owner: 'CERTAUTH',
 *     usage: 'CERTAUTH',
 *     status: 'TRUST',
 *     default: false,
 *     pem: '-----BEGIN CERTIFICATE-----\n' +
 *           certificate content in base64
 *          '-----END CERTIFICATE-----'
 *   },
 *   ...
 * ]
 */
CAChain = keyring.getCAchain("USERID", "Keyring", "Cert_label");
console.log("CA chain of the certificate: ");
console.log(CAChain);


/*
 * Get a specific certificate and its private key (in PEM/DER format).
 *
 * returns an object containing certificate and private key:
 * 
 * {
 *   certificate: '-----BEGIN CERTIFICATE-----\n' +
 *                 certificate content in base64
 *                '-----END CERTIFICATE-----'
 *
 *   key: '-----BEGIN PRIVATE KEY-----\n' +
 *         certificate content in base64
 *        '-----END PRIVATE KEY-----'
 * }
 */
const data_pem = keyring.getPemEncodedData("USERID", "Keyring", "Cert_label");
// const data_der = keyring.getDerEncodedData("USERID", "Keyring", "Cert_label");

const options = {
    key: data_pem.key,
    cert: data_pem.certificate,
};

https.createServer(options, (req, res) => {
    res.writeHead(200);
    res.end('hello, i\'m running on keyring: node: ' + process.version + ', arch: '
        + os.arch() + ', platform: ' + os.platform() + '\n');
}).listen(12345);