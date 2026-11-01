// Node-API bindings for the reentrant SHA-256 crypt and SHA-512 crypt
// implementations.  Argument validation beyond basic type checks lives in
// shacrypt.js; the native layer only guarantees it cannot be misused.

#include <napi.h>

#include <cstring>
#include <utility>
#include <vector>

#include "secure_wipe.h"
#include "sha256crypt.h"
#include "sha512crypt.h"

namespace {

struct Sha256 {
  static constexpr const char* kName = "shacrypt:sha256";
  static constexpr int kBufLen = SHA256_CRYPT_OUTPUT_MAX;
  static char* Run(const char* key, const char* salt, char* buf, int len) {
    return sha256_crypt_r(key, salt, buf, len);
  }
};

struct Sha512 {
  static constexpr const char* kName = "shacrypt:sha512";
  static constexpr int kBufLen = SHA512_CRYPT_OUTPUT_MAX;
  static char* Run(const char* key, const char* salt, char* buf, int len) {
    return sha512_crypt_r(key, salt, buf, len);
  }
};

// A UTF-8 copy of a JavaScript string in a buffer that is wiped when
// destroyed.  It is read straight from the engine, so no intermediate
// standard-library string copy of the secret is ever made.  Moving it
// transfers the heap buffer rather than copying bytes, which matters because
// a short standard string is moved by copying its inline bytes, leaving an
// unwiped copy in the moved-from object.
class SecretString {
 public:
  SecretString() = default;
  SecretString(SecretString&&) = default;
  SecretString(const SecretString&) = delete;
  // Assignment would have to wipe the old buffer first; nothing needs it.
  SecretString& operator=(SecretString&&) = delete;
  SecretString& operator=(const SecretString&) = delete;
  ~SecretString() { Wipe(); }

  bool Read(napi_env env, napi_value value) {
    size_t length = 0;
    if (napi_get_value_string_utf8(env, value, nullptr, 0, &length) !=
        napi_ok) {
      return false;
    }
    buf_.assign(length + 1, '\0');
    size_t copied = 0;
    if (napi_get_value_string_utf8(env, value, buf_.data(), buf_.size(),
                                   &copied) != napi_ok) {
      return false;
    }
    length_ = copied;
    return true;
  }

  const char* c_str() const { return buf_.data(); }

  bool ContainsNul() const {
    return std::memchr(buf_.data(), '\0', length_) != nullptr;
  }

  void Wipe() {
    if (!buf_.empty()) secure_wipe(buf_.data(), buf_.size());
  }

 private:
  std::vector<char> buf_;
  size_t length_ = 0;
};

struct Inputs {
  SecretString key;
  SecretString salt;
};

// Reads (password, salt) from the first two arguments.  On failure a
// JavaScript exception is pending and false is returned.
bool ReadInputs(const Napi::CallbackInfo& info, Inputs& in) {
  Napi::Env env = info.Env();
  if (info.Length() < 2 || !info[0].IsString() || !info[1].IsString()) {
    Napi::TypeError::New(env, "password and salt must be strings")
        .ThrowAsJavaScriptException();
    return false;
  }
  if (!in.key.Read(env, info[0]) || !in.salt.Read(env, info[1])) {
    Napi::Error::New(env, "could not read arguments")
        .ThrowAsJavaScriptException();
    return false;
  }
  // The C implementation works on NUL-terminated strings, so an embedded
  // NUL would silently truncate the password.
  if (in.key.ContainsNul() || in.salt.ContainsNul()) {
    Napi::TypeError::New(env,
                         "password and salt must not contain NUL characters")
        .ThrowAsJavaScriptException();
    return false;
  }
  return true;
}

template <typename Algo>
Napi::Value CryptSync(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  Inputs in;
  if (!ReadInputs(info, in)) return env.Undefined();

  char buf[Algo::kBufLen];
  if (Algo::Run(in.key.c_str(), in.salt.c_str(), buf, Algo::kBufLen) ==
      nullptr) {
    Napi::Error::New(env, "hash computation failed")
        .ThrowAsJavaScriptException();
    return env.Undefined();
  }
  return Napi::String::New(env, buf);
}

template <typename Algo>
class CryptWorker : public Napi::AsyncWorker {
 public:
  CryptWorker(const Napi::Function& callback, Inputs&& in)
      : Napi::AsyncWorker(callback, Algo::kName), in_(std::move(in)) {}

  // Runs on a libuv thread-pool thread.  Every buffer it touches is owned
  // by this worker, so concurrent workers never share state.
  void Execute() override {
    if (Algo::Run(in_.key.c_str(), in_.salt.c_str(), buf_, Algo::kBufLen) ==
        nullptr) {
      SetError("hash computation failed");
    }
    in_.key.Wipe();  // the password is not needed after this point
  }

  std::vector<napi_value> GetResult(Napi::Env env) override {
    return {env.Null(), Napi::String::New(env, buf_)};
  }

  void WipeInputs() { in_.key.Wipe(); }

 private:
  Inputs in_;
  char buf_[Algo::kBufLen];
};

template <typename Algo>
Napi::Value CryptAsync(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  if (info.Length() < 3 || !info[2].IsFunction()) {
    Napi::TypeError::New(env, "callback must be a function")
        .ThrowAsJavaScriptException();
    return env.Undefined();
  }
  Inputs in;
  if (!ReadInputs(info, in)) return env.Undefined();

  // With C++ exceptions disabled, a failure in the AsyncWorker constructor
  // or in Queue() only sets a pending JavaScript exception, and nothing
  // else would clean the worker up, so its password copy would never be
  // wiped.  Neither failure happens in practice; both are handled anyway.
  auto* worker =
      new CryptWorker<Algo>(info[2].As<Napi::Function>(), std::move(in));
  if (env.IsExceptionPending()) {
    // The constructor can fail before it creates the async work handle, in
    // which case node-addon-api leaves that handle uninitialised and the
    // worker cannot be safely destroyed.  Wipe the secret and abandon it.
    worker->WipeInputs();
    return env.Undefined();
  }
  worker->Queue();
  if (env.IsExceptionPending()) {
    delete worker;  // construction succeeded, so the destructor is safe
    return env.Undefined();
  }
  // On success the worker deletes itself after the callback has run.
  return env.Undefined();
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  exports.Set("sha256crypt",
              Napi::Function::New(env, CryptSync<Sha256>, "sha256crypt"));
  exports.Set("sha512crypt",
              Napi::Function::New(env, CryptSync<Sha512>, "sha512crypt"));
  exports.Set("sha256cryptasync", Napi::Function::New(env, CryptAsync<Sha256>,
                                                      "sha256cryptasync"));
  exports.Set("sha512cryptasync", Napi::Function::New(env, CryptAsync<Sha512>,
                                                      "sha512cryptasync"));
  return exports;
}

}  // namespace

NODE_API_MODULE(shacrypt, Init)
