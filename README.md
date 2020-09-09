# keyring-utilities
Various key ring utilities that interact with z/OS RACF key rings using R_datalib API

## Nodejs keyring addon
The addon can get a certificate from the keyring using [R_datalib API](https://www.ibm.com/support/knowledgecenter/SSLTBW_2.4.0/com.ibm.zos.v2r4.ichd100/datalib.htm). The addon is written using [N-API (C API)](https://nodejs.org/dist/latest-v12.x/docs/api/n-api.html#n_api_n_api) which should ensure ABI stability across Node.js versions that implements N-API. More information [here](https://medium.com/the-node-js-collection/n-api-next-generation-apis-for-node-js-native-addons-available-across-all-lts-release-lines-4f35b781f00e)

### Building addon
To build the addon, Node.js v8.16.0 or higher is required. The C/C++ toolchain has to be installed and configured for your Node.js SDK. To build and install the addon locally on z/OS, clone the repository and run the following commands from the root dir of the repository:

```npm install```  

```npm run prebuild``` 

### Installation
The [prebuildify](https://nodejs.org/api/n-api.html#n_api_prebuildify) tool is used to include prebuilt binaries to the package that is published to npm. That means, you can simply install the native addon from npm using the following command.

```npm install keyring_js``` 

In this case, you don't need the C/C++ toolchain for building native addons.

### Example and usage
See the [example.js](./example.js) file to see how the addon is used and how to test its functionality.

### Notes
After installing the keyring_js package using `npm install keyring_js` make sure that installed files in the `node_modules/keyring_js/` are tagged as ASCII files.
For example, you should see:
```
$: >ls -T node_modules/keyring_js/
t ISO8859-1   T=on  LICENSE
t ISO8859-1   T=on  README.md
t ISO8859-1   T=on  binding.gyp
t ISO8859-1   T=on  example.js
t ISO8859-1   T=on  index.js
t ISO8859-1   T=on  keyring_js.c
t ISO8859-1   T=on  package.json
                    prebuilds
                    src

```

## keyring-util tool
See [README.md](./keyring-util/README.md)
