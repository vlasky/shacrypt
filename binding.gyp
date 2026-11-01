{
  "targets": [
    {
      "target_name": "shacrypt",
      "sources": [
        "src/sha256crypt.c",
        "src/sha512crypt.c",
        "src/shacrypt.cc"
      ],
      "include_dirs": [
        "<!@(node -p \"require('node-addon-api').include\")"
      ],
      "defines": [
        "NAPI_VERSION=8",
        "NAPI_DISABLE_CPP_EXCEPTIONS"
      ],
      "cflags": ["-Wall"],
      "cflags_cc": ["-Wall"],
      "xcode_settings": {
        "WARNING_CFLAGS": ["-Wall"]
      }
    }
  ]
}
