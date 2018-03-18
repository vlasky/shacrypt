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
  Nan::Utf8String key(info[0]);
  Nan::Utf8String salt(info[1]);

  info.GetReturnValue().Set(Nan::New(sha256_crypt(*key, *salt)).ToLocalChecked());
}

NAN_METHOD(sha512crypt) {
  Nan::Utf8String key(info[0]);
  Nan::Utf8String salt(info[1]);

  info.GetReturnValue().Set(Nan::New(sha512_crypt(*key, *salt)).ToLocalChecked());
}


class SHA256CryptWorker : public AsyncWorker {

  public:
    SHA256CryptWorker(Callback* callback, const Nan::Utf8String& key, const Nan::Utf8String& salt) : AsyncWorker(callback, "shacrypt:SHA256CryptWorker"), key(*key), salt(*salt) {
    }

    void Execute() {
      result = sha256_crypt(key.c_str(), salt.c_str());
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
      result = sha512_crypt(key.c_str(), salt.c_str());
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
  Nan::Utf8String key(info[0]);
  Nan::Utf8String salt(info[1]);

  Callback *callback = new Callback(To<Function>(info[2]).ToLocalChecked());
  AsyncQueueWorker(new SHA256CryptWorker(callback, key, salt));
}

NAN_METHOD(sha512cryptasync) {
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

