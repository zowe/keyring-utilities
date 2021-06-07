const spawnSync = require('child_process').spawnSync;
const expect = require('chai').expect;
const keyring = require('../');

const username = require('os').userInfo().username;
const keyringName = 'TESTRING'
const certAlias = 'testalias'
const usage = 'PERSONAL'
const status = 'TRUST'
const testp12 = 'testcert.p12'

describe('Test keyring_js', function () {
  this.timeout(0);

  before("set up", function() {
    buildKeyringUtil();
    createAndSetKeyring();
  });

  it('listKeyring(): verify keyring content', function () {
    result = keyring.listKeyring(username, keyringName);
    expect(result).to.have.lengthOf(1);
    expect(result[0].label).to.equal(certAlias);
    expect(result[0].owner).to.equal(username);
    expect(result[0].usage).to.equal(usage);
    expect(result[0].status).to.equal(status);
    expect(result[0].default).to.equal(false);
  });

  it('listKeyring(): verify not enough parameters', function () {
    try {
      keyring.listKeyring(username);
    } catch(e) {
      expect(e.message).to.equal('Second parameter has wrong argument type');
    }
  });

  it('listKeyring(): verify keyring does not exist', function () {
    try {
      keyring.listKeyring(username, 'NOTEXIST');
    } catch(e) {
      expect(e.message).to.equal('R_datalib call failed: function code: 01, SAF rc: 8, RACF rc: 8, RACF rsn: 84\n');
    }
  });

  it('listKeyring(): verify userid does not exist', function () {
    try {
      keyring.listKeyring('UNKNWN99', keyringName);
    } catch(e) {
      expect(e.message).to.equal('R_datalib call failed: function code: 01, SAF rc: 8, RACF rc: 8, RACF rsn: 84\n');
    }
  });

  it('listKeyring(): verify userid name too long', function () {
    try {
      keyring.listKeyring('LOOOOONGNAME', keyringName);
    } catch(e) {
      expect(e.message).to.equal('First parameter is too long. Parameter can be up to 8 bytes long');
    }
  });

  it('listKeyring(): verify keyring name too long', function () {
    try {
      keyring.listKeyring(username, 'looooooooooooooooooooooooooooooooooooooooooooooooo'
                                  + 'oooooooooooooooooooooooooooooooooooooooooooooooooo'
                                  + 'oooooooooooooooooooooooooooooooooooooooooooooooooo'
                                  + 'oooooooooooooooooooooooooooooooooooooooooooooooooo'
                                  + 'ooooooooooooooooooooooongKeyringLabel');
    } catch(e) {
      expect(e.message).to.equal('Second parameter is too long. Parameter can be up to 236 bytes long');
    }
  });

  it('getPemEncodedData(): verify returned data', function () {
    result = keyring.getPemEncodedData(username, keyringName, certAlias);
    expect(result.key).to.contain('-----BEGIN PRIVATE KEY-----\nMIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdw');
    expect(result.key).to.contain('-----END PRIVATE KEY-----');
    expect(result.certificate).to.contain('-----BEGIN CERTIFICATE-----\nMIICFTCCAbmgAwIBAgIEFajL/jAMBggqhkjOPQQDAgUAMH8xCzAJBgNVBAYTAkNa\nMQ8wDQY');
    expect(result.certificate).to.contain('-----END CERTIFICATE-----');
  });

  it('getPemEncodedData(): verify not enough parameters', function () {
    try {
      keyring.getPemEncodedData();
    } catch(e) {
      expect(e.message).to.equal('First parameter has wrong argument type');
    }
  });

  it('getPemEncodedData(): verify not enough parameters', function () {
    try {
      keyring.getPemEncodedData(username);
    } catch(e) {
      expect(e.message).to.equal('Second parameter has wrong argument type');
    }
  });

  it('getPemEncodedData(): verify not enough parameters', function () {
    try {
      keyring.getPemEncodedData(username, keyringName);
    } catch(e) {
      expect(e.message).to.equal('Third parameter has wrong argument type');
    }
  });

  it('getPemEncodedData(): verify keyring does not exist', function () {
    try {
      keyring.getPemEncodedData(username, 'NOTEXIST', certAlias);
    } catch(e) {
      expect(e.message).to.equal('R_datalib call failed: function code: 01, SAF rc: 8, RACF rc: 8, RACF rsn: 84\n');
    }
  });

  it('getPemEncodedData(): verify userid does not exist', function () {
    try {
      keyring.getPemEncodedData('UNKNWN99', keyringName, certAlias);
    } catch(e) {
      expect(e.message).to.equal('R_datalib call failed: function code: 01, SAF rc: 8, RACF rc: 8, RACF rsn: 84\n');
    }
  });

  it('getPemEncodedData(): verify certificate label does not exist', function () {
    try {
      keyring.getPemEncodedData(username, keyringName, 'certdoesnotexist');
    } catch(e) {
      expect(e.message).to.equal('R_datalib call failed: function code: 01, SAF rc: 8, RACF rc: 8, RACF rsn: 44\n');
    }
  });

  it('getPemEncodedData(): verify userid name too long', function () {
    try {
      keyring.getPemEncodedData('LOOOOONGNAME', keyringName, certAlias);
    } catch(e) {
      expect(e.message).to.equal('First parameter is too long. Parameter can be up to 8 bytes long');
    }
  });

  it('getPemEncodedData(): verify keyring name too long', function () {
    try {
      keyring.getPemEncodedData(username, 'looooooooooooooooooooooooooooooooooooooooooooooooo'
                                  + 'oooooooooooooooooooooooooooooooooooooooooooooooooo'
                                  + 'oooooooooooooooooooooooooooooooooooooooooooooooooo'
                                  + 'oooooooooooooooooooooooooooooooooooooooooooooooooo'
                                  + 'ooooooooooooooooooooooongKeyringLabel', certAlias);
    } catch(e) {
      expect(e.message).to.equal('Second parameter is too long. Parameter can be up to 236 bytes long');
    }
  });

  it('getPemEncodedData(): verify certificate label too long', function () {
    try {
      keyring.getPemEncodedData(username, keyringName, 'looooooooooooooooooooooooongLabel');
    } catch(e) {
      expect(e.message).to.equal('Third parameter is too long. Parameter can be up to 32 bytes long');
    }
  });

  after("tear down",function() {
    cleanUpKeyringAndCert();
  });
});

function createAndSetKeyring() {
  spawnCommand('chtag', ['-b', testp12], './keyring-util');

  executeKeyringUtil(['NEWRING', username, keyringName]);
  executeKeyringUtil(['IMPORT', username, keyringName, certAlias, usage, testp12, 'password']);
}

function cleanUpKeyringAndCert() {
  executeKeyringUtil(['DELRING', username, keyringName]);
  executeKeyringUtil(['DELCERT', username, '*', certAlias]);
}

function buildKeyringUtil() {
  spawnCommand('build.sh', [], './keyring-util');
}

function executeKeyringUtil(param) {
  console.log('keyring-util ' + param.toString().replace(/,/g,' '));
  spawnCommand('keyring-util', param, './keyring-util');
}

function spawnCommand(command, param, cwd) {
  res = spawnSync(command, param, {
    cwd: cwd
  });
  console.log(res.stdout.toString());
  console.log(res.stderr.toString());
}

