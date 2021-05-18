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

results = keyring.listKeyring("USERID", "Keyring");

let certificate;
for (const item of results) {
  console.log(item);
}

// const data_der = keyring.getDerEncodedData("USERID", "Keyring", "Cert_label");

const data_pem = keyring.getPemEncodedData("USERID", "Keyring", "Cert_label");

const options = {
    key: data_pem.key,
    cert: data_pem.certificate,
};

https.createServer(options, (req, res) => {
    res.writeHead(200); 
    res.end('hello, i\'m running on keyring: node: ' + process.version + ', arch: ' 
        + os.arch() + ', platform: ' + os.platform() + '\n'); 
}).listen(12345);