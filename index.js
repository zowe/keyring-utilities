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
const X509 = require('jsrsasign').X509;

module.exports.getDerEncodedData = getDerEncodedData;
module.exports.getPemEncodedData = getPemEncodedData;
module.exports.listKeyring = listKeyring;
module.exports.getCAchain = getCAchain;

function getCAchain(userid, keyring, label) {
  caList = [];
  keyringContent = listKeyring(userid, keyring);

  let certObject;
  // locate certificate whose CA chain we are looking for
  for (const item of keyringContent) {
    if (item.label == label) {
      certObject = item;
    }
  }

  if (certObject == undefined)
    throw Error('The ' + label + ' certificate is not found in the ' + userid + '/' + keyring + ' keyring');

  certToCheck = new X509(certObject.pem);
  issuer = certToCheck.getIssuer().str;
  subject = certToCheck.getSubject().str;

  // selfsigned
  if (issuer == subject) {
    return caList;
  }

  while (true) {
    tempCertObject = findCertWithSubjectOf(issuer, keyringContent);
    if (tempCertObject == undefined) { // no more cert found, get out
      break;
    } else {
      if(isRoot(tempCertObject)) {
        caList.push(tempCertObject); // add root and get out
        break;
      } else {
        caList.push(tempCertObject); // add intermediate and check for next one
        issuer = new X509(tempCertObject.pem).getIssuer().str
        continue;
      }
    }
  }
  return caList;
}

function isRoot(certObj) {
  let cert = new X509(certObj.pem);
  if (cert.getIssuer().str == cert.getSubject().str) {
    return true;
  } else {
    return false;
  }
}

function findCertWithSubjectOf(issuer, keyringContent) {
  for (const item of keyringContent) {
    subject = new X509(item.pem).getSubject().str;
    if (subject == issuer) {
      return item;
    }
  }
  return undefined;
}

function listKeyring(userid, keyring){
  return binding.listKeyring(userid, keyring);
}

function getDerEncodedData(userid, keyring, label) {
    return binding.getData(userid, keyring, label, "der");
}

function getPemEncodedData(userid, keyring, label) {
    return binding.getData(userid, keyring, label, "pem");
}