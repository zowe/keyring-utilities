/*
* This program and the accompanying materials are made available under the terms of the *
* Eclipse Public License v2.0 which accompanies this distribution, and is available at *
* https://www.eclipse.org/legal/epl-v20.html                                      *
*                                                                                 *
* SPDX-License-Identifier: EPL-2.0                                                *
*                                                                                 *
* Copyright Contributors to the Zowe Project.                                     *
*/

var binding = require('node-gyp-build')(__dirname);

module.exports.getDerEncodedData = getDerEncodedData;
module.exports.getPemEncodedData = getPemEncodedData;
module.exports.listKeyring = listKeyring;


function listKeyring(userid, keyring){
  return binding.listKeyring(userid, keyring);
}

function getDerEncodedData(userid, keyring, label) {
    return binding.getData(userid, keyring, label, "der");
}

function getPemEncodedData(userid, keyring, label) {
    return binding.getData(userid, keyring, label, "pem");
}