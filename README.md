# keyring-utilities
Various key ring utilities that interact with z/OS RACF key rings using R_datalib API

## Nodejs keyring addon
The addon can get a certificate from the keyring using [R_datalib API](https://www.ibm.com/support/knowledgecenter/SSLTBW_2.4.0/com.ibm.zos.v2r4.ichd100/datalib.htm). The addon is written using [N-API (C API)](https://nodejs.org/dist/latest-v12.x/docs/api/n-api.html#n_api_n_api) which should ensure ABI stability across Node.js versions that implements N-API. More information [here](https://medium.com/the-node-js-collection/n-api-next-generation-apis-for-node-js-native-addons-available-across-all-lts-release-lines-4f35b781f00e)

### Building and installation
To build the addon, Node.js v8.16.0 or higher is required. The C/C++ toolchain has to be installed and configured for your Node.js SDK. To build and install the addon, clone the repository and run the 
```npm install```  command from the root dir of the repository.

### Example and usage
See the [example.js](./example.js) file to see how the addon is used and how to test its functionality.

## keyring-util tool
See [README.md](./keyring-util/README.md)
