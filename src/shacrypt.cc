#include <node.h>
#include <v8.h>
#include <nan.h>

#include "sha256crypt.h"
#include "sha512crypt.h"

using namespace v8;
using namespace node;

using std::string;

using Nan::AsyncQueueWorker;
using Nan::AsyncWorker;
using Nan::Callback;
using Nan::HandleScope;
using Nan::New;
using Nan::Null;
using Nan::To;

NAN_METHOD(sha256crypt) {
  if (info.Length() < 2) {
    Nan::ThrowError("Wrong number of arguments");
    return;
  }

  if (!info[0]->IsString() || !info[1]->IsString()) {
    Nan::ThrowTypeError("Arguments must be strings");
    return;
  }

  Nan::Utf8String key(info[0]);
  Nan::Utf8String salt(info[1]);

  const char* result = sha256_crypt(*key, *salt);
  if (!result) {
    Nan::ThrowError("sha256_crypt failed");
    return;
  }

  info.GetReturnValue().Set(Nan::New(result).ToLocalChecked());
}

NAN_METHOD(sha512crypt) {
  if (info.Length() < 2) {
    Nan::ThrowError("Wrong number of arguments");
    return;
  }

  if (!info[0]->IsString() || !info[1]->IsString()) {
    Nan::ThrowTypeError("Arguments must be strings");
    return;
  }

  Nan::Utf8String key(info[0]);
  Nan::Utf8String salt(info[1]);

  const char* result = sha512_crypt(*key, *salt);
  if (!result) {
    Nan::ThrowError("sha512_crypt failed");
    return;
  }

  info.GetReturnValue().Set(Nan::New(result).ToLocalChecked());
}


class SHA256CryptWorker : public AsyncWorker {

  public:
    SHA256CryptWorker(Callback* callback, const Nan::Utf8String& key, const Nan::Utf8String& salt) : AsyncWorker(callback, "shacrypt:SHA256CryptWorker"), key(*key), salt(*salt) {
    }

    void Execute() {
      const char* crypt_result = sha256_crypt(key.c_str(), salt.c_str());
      if (!crypt_result) {
        SetErrorMessage("sha256_crypt failed");
        return;
      }
      result = crypt_result;
    }

    void HandleOKCallback() {
      Local<Value> argv[] = { Null(), Nan::New(result).ToLocalChecked() };
      callback->Call(2, argv, async_resource);
    }

  private:
    string key;
    string salt;
    string result;
};

class SHA512CryptWorker : public AsyncWorker {

  public:
    SHA512CryptWorker(Callback* callback, const Nan::Utf8String& key, const Nan::Utf8String& salt) : AsyncWorker(callback, "shacrypt:SHA512CryptWorker"), key(*key), salt(*salt) {
    }

    void Execute() {
      const char* crypt_result = sha512_crypt(key.c_str(), salt.c_str());
      if (!crypt_result) {
        SetErrorMessage("sha512_crypt failed");
        return;
      }
      result = crypt_result;
    }

    void HandleOKCallback() {
      Local<Value> argv[] = { Null(), Nan::New(result).ToLocalChecked() };
      callback->Call(2, argv, async_resource);
    }

  private:
    string key;
    string salt;
    string result;
};

NAN_METHOD(sha256cryptasync) {
  if (info.Length() < 3) {
    Nan::ThrowError("Wrong number of arguments");
    return;
  }

  if (!info[0]->IsString() || !info[1]->IsString()) {
    Nan::ThrowTypeError("First two arguments must be strings");
    return;
  }

  if (!info[2]->IsFunction()) {
    Nan::ThrowTypeError("Third argument must be a function");
    return;
  }

  Nan::Utf8String key(info[0]);
  Nan::Utf8String salt(info[1]);

  Callback *callback = new Callback(To<Function>(info[2]).ToLocalChecked());
  AsyncQueueWorker(new SHA256CryptWorker(callback, key, salt));
}

NAN_METHOD(sha512cryptasync) {
  if (info.Length() < 3) {
    Nan::ThrowError("Wrong number of arguments");
    return;
  }

  if (!info[0]->IsString() || !info[1]->IsString()) {
    Nan::ThrowTypeError("First two arguments must be strings");
    return;
  }

  if (!info[2]->IsFunction()) {
    Nan::ThrowTypeError("Third argument must be a function");
    return;
  }

  Nan::Utf8String key(info[0]);
  Nan::Utf8String salt(info[1]);

  Callback *callback = new Callback(To<Function>(info[2]).ToLocalChecked());
  AsyncQueueWorker(new SHA512CryptWorker(callback, key, salt));
}


NAN_MODULE_INIT(init) {
  Nan::Set(target, Nan::New("sha256crypt").ToLocalChecked(),
    Nan::GetFunction(Nan::New<FunctionTemplate>(sha256crypt)).ToLocalChecked());
  Nan::Set(target, Nan::New("sha512crypt").ToLocalChecked(),
    Nan::GetFunction(Nan::New<FunctionTemplate>(sha512crypt)).ToLocalChecked());

  Nan::Set(target, Nan::New("sha256cryptasync").ToLocalChecked(),
    Nan::GetFunction(Nan::New<FunctionTemplate>(sha256cryptasync)).ToLocalChecked());
  Nan::Set(target, Nan::New("sha512cryptasync").ToLocalChecked(),
    Nan::GetFunction(Nan::New<FunctionTemplate>(sha512cryptasync)).ToLocalChecked());
}


NODE_MODULE(shacrypt, init);

