{
  "targets": [
    {
      "target_name": "keyring_js",
      "cflags": [  "-qascii -qarch=9" ],
      "sources": [ "keyring_js.c", "src/c/keyring_get.c", "src/c/keyring_service.c"],
      "include_dirs": ["src/h"],
      "libraries": ["/usr/lib/GSKCMS64.x"],
      "defines": [ "_AE_BIMODAL=1" ]
    }
  ]
}
