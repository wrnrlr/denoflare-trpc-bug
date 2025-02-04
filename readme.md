# Denoflare trpc bug

Denoflare works OK without trpc

```
deno run -A --unstable-worker-options \
  https://raw.githubusercontent.com/skymethod/denoflare/f414afa279f0ab095eb40505f51afa913adc2d7e/cli/cli.ts \
  serve no-trpc.ts
```

But when running this with a trpc server, it complains about the `Deno` namespace

```
deno run -A --unstable-worker-options \
  https://raw.githubusercontent.com/skymethod/denoflare/f414afa279f0ab095eb40505f51afa913adc2d7e/cli/cli.ts \
  serve bug.ts
```

```
Compiling https://raw.githubusercontent.com/skymethod/denoflare/f414afa279f0ab095eb40505f51afa913adc2d7e/cli-webworker/worker.ts into worker contents...
{ out: "", err: "", success: true }
Bundled https://raw.githubusercontent.com/skymethod/denoflare/f414afa279f0ab095eb40505f51afa913adc2d7e/cli-webworker/worker.ts (esbuild) in 148ms
runScript: bug.ts
{ out: "", err: "", success: true }
Bundled bug.ts (esbuild) in 128ms
worker: start
Error running script ReferenceError: Deno is not defined
    at denoEnvGet (ext:deno_node/_process/process.ts:30:34)
    at Object.get (ext:deno_node/_process/process.ts:45:22)
    at initTRPCInner (blob:null/93ce3d01-69be-4061-984b-8d714de23c75:668:55)
    at _TRPCBuilder.create (blob:null/93ce3d01-69be-4061-984b-8d714de23c75:658:29)
    at blob:null/93ce3d01-69be-4061-984b-8d714de23c75:1194:18
```


<details>
  <summary>Full stacktrace with --verbose</summary>
loadConfig: path=undefined
Compiling https://raw.githubusercontent.com/skymethod/denoflare/f414afa279f0ab095eb40505f51afa913adc2d7e/cli-webworker/worker.ts into worker contents...
{ out: "", err: "", success: true }
delete globalThis.Deno;
// https://raw.githubusercontent.com/skymethod/denoflare/f414afa279f0ab095eb40505f51afa913adc2d7e/common/console.ts
var consoleLog = console.log;
var consoleWarn = console.warn;

// https://raw.githubusercontent.com/skymethod/denoflare/f414afa279f0ab095eb40505f51afa913adc2d7e/common/rpc_channel.ts
var RpcChannel = class _RpcChannel {
  static VERBOSE = false;
  requests = /* @__PURE__ */ new Map();
  postMessage;
  requestDataHandlers = /* @__PURE__ */ new Map();
  tag;
  nextRequestNum = 1;
  constructor(tag, postMessage) {
    this.tag = tag;
    this.postMessage = postMessage;
  }
  async receiveMessage(data) {
    if (isRpcResponse(data)) {
      if (_RpcChannel.VERBOSE) consoleLog(`${this.tag}: receiveMessage response ${data.rpcMethod}`);
      const request = this.requests.get(data.num);
      if (request) {
        this.requests.delete(data.num);
        request.onRpcResponse(data);
      }
      return true;
    }
    if (isRpcRequest(data)) {
      if (_RpcChannel.VERBOSE) consoleLog(`${this.tag}: receiveMessage request ${data.rpcMethod}`);
      const { rpcMethod, num } = data;
      const handler = this.requestDataHandlers.get(rpcMethod);
      if (handler) {
        let responseData;
        let transfer = [];
        let error;
        try {
          responseData = await handler(data.data);
          if (typeof responseData === "object" && responseData.data !== void 0 && Array.isArray(responseData.transfer)) {
            transfer = responseData.transfer;
            responseData = responseData.data;
          }
        } catch (e) {
          error = e;
        }
        if (error) {
          this.postMessage({ responseKind: "error", num, rpcMethod, error: { message: error.message, name: error.name, stack: error.stack } }, transfer);
        } else {
          this.postMessage({ responseKind: "ok", num, rpcMethod, data: responseData }, transfer);
        }
      }
      return true;
    }
    return false;
  }
  fireRequest(rpcMethod, data) {
    this.sendRequest(rpcMethod, data, () => {
    }).catch((e) => {
      console.error(`fireRequest error in ${rpcMethod}`, e.stack || e);
    });
  }
  sendRequest(rpcMethod, data, unpackResponseDataFn, transfer = []) {
    const num = this.nextRequestNum++;
    const request = { num, onRpcResponse: () => {
    } };
    this.requests.set(num, request);
    const rt = new Promise((resolve, reject) => {
      request.onRpcResponse = (rpcResponse) => {
        if (rpcResponse.rpcMethod !== rpcMethod) {
          reject(new Error(`Bad rpcResponse.rpcMethod: ${rpcResponse.rpcMethod}, expected ${rpcMethod}`));
        } else if (rpcResponse.responseKind === "error") {
          reject(rpcResponse.error);
        } else if (rpcResponse.responseKind === "ok") {
          resolve(unpackResponseDataFn(rpcResponse.data));
        } else {
          reject(new Error(`Unknown rpcResponse.responseKind: ${rpcResponse}`));
        }
      };
    });
    const rpcRequest = { requestKind: "rpc", rpcMethod, num, data };
    if (_RpcChannel.VERBOSE) consoleLog(`${this.tag}: sendRequest ${rpcRequest.rpcMethod}`);
    this.postMessage(rpcRequest, transfer);
    return rt;
  }
  addRequestHandler(rpcMethod, requestDataHandler) {
    this.requestDataHandlers.set(rpcMethod, requestDataHandler);
  }
};
function isRpcResponse(data) {
  return typeof data.num === "number" && typeof data.rpcMethod === "string" && typeof data.responseKind === "string";
}
function isRpcRequest(data) {
  return typeof data.num === "number" && typeof data.rpcMethod === "string" && typeof data.requestKind === "string";
}

// https://raw.githubusercontent.com/skymethod/denoflare/f414afa279f0ab095eb40505f51afa913adc2d7e/common/rpc_kv_namespace.ts
var RpcKVNamespace = class {
  // deno-lint-ignore no-explicit-any
  async get(key, opts = { type: "text" }) {
    if (typeof key === "string") {
      if (opts.type === "arrayBuffer" || opts === "arrayBuffer") {
        const { kvNamespace } = this;
        const req = { type: "arrayBuffer", key, kvNamespace };
        return await this.channel.sendRequest("kv-namespace-get", req, (responseData) => {
          const res = responseData;
          if (res.type === "arrayBuffer") return res.buffer;
          throw new Error(`Bad res.type ${res.type}, expected arrayBuffer`);
        });
      } else if (opts.type === "json" || opts === "json") {
        const { kvNamespace } = this;
        const req = { type: "json", key, kvNamespace };
        return await this.channel.sendRequest("kv-namespace-get", req, (responseData) => {
          const res = responseData;
          if (res.type === "json") return res.record;
          throw new Error(`Bad res.type ${res.type}, expected json`);
        });
      } else if (opts.type === "text" || opts === "text") {
        const { kvNamespace } = this;
        const req = { type: "text", key, kvNamespace };
        return await this.channel.sendRequest("kv-namespace-get", req, (responseData) => {
          const res = responseData;
          if (res.type === "text") return res.text;
          throw new Error(`Bad res.type ${res.type}, expected json`);
        });
      }
    }
    throw new Error(`RpcKVNamespace.get not implemented. key=${typeof key} ${key}, opts=${JSON.stringify(opts)}`);
  }
  // deno-lint-ignore no-explicit-any
  async getWithMetadata(key, opts = { type: "text" }) {
    if (typeof key === "string") {
      if (opts.type === "json" || opts === "json") {
        const { kvNamespace } = this;
        const req = { type: "json", key, kvNamespace, withMetadata: true };
        const { record, metadata } = await this.channel.sendRequest("kv-namespace-get", req, (responseData) => {
          const res = responseData;
          if (res.type === "json") return { record: res.record, metadata: res.metadata };
          throw new Error(`Bad res.type ${res.type}, expected json, res=${JSON.stringify(res)}`);
        });
        let rt = null;
        if (record) {
          rt = { metadata: metadata || null, value: record };
        }
        return rt;
      }
      if (opts.type === "text" || opts === "text") {
        const { kvNamespace } = this;
        const req = { type: "text", key, kvNamespace, withMetadata: true };
        const { text, metadata } = await this.channel.sendRequest("kv-namespace-get", req, (responseData) => {
          const res = responseData;
          if (res.type === "text") return { text: res.text, metadata: res.metadata };
          throw new Error(`Bad res.type ${res.type}, expected text, res=${JSON.stringify(res)}`);
        });
        let rt = null;
        if (text) {
          rt = { metadata: metadata || null, value: text };
        }
        return rt;
      }
    }
    throw new Error(`RpcKVNamespace.getWithMetadata not implemented. key=${typeof key} ${key}, opts=${JSON.stringify(opts)}`);
  }
  put(_key, _value, _opts) {
    throw new Error(`RpcKVNamespace.put not implemented.`);
  }
  delete(_key) {
    throw new Error(`RpcKVNamespace.delete not implemented.`);
  }
  list(_opts) {
    throw new Error(`KVNamespaceRpcStub.list not implemented.`);
  }
  kvNamespace;
  channel;
  constructor(kvNamespace, channel) {
    this.kvNamespace = kvNamespace;
    this.channel = channel;
  }
};

// https://raw.githubusercontent.com/skymethod/denoflare/f414afa279f0ab095eb40505f51afa913adc2d7e/common/noop_cf_global_caches.ts
var NoopCfGlobalCaches = class {
  default = new NoopCfCache();
  namedCaches = /* @__PURE__ */ new Map();
  open(cacheName) {
    const existing = this.namedCaches.get(cacheName);
    if (existing) return Promise.resolve(existing);
    const cache = new NoopCfCache();
    this.namedCaches.set(cacheName, cache);
    return Promise.resolve(cache);
  }
};
var NoopCfCache = class {
  put(_request, _response) {
    return Promise.resolve(void 0);
  }
  match(_request, _options) {
    return Promise.resolve(void 0);
  }
  delete(_request, _options) {
    return Promise.resolve(false);
  }
};

// https://raw.githubusercontent.com/skymethod/denoflare/f414afa279f0ab095eb40505f51afa913adc2d7e/common/fetch_util.ts
var FetchUtil = class {
  static VERBOSE = false;
};
function cloneRequestWithHostname(request, hostname) {
  const url = new URL(request.url);
  if (url.hostname === hostname) return request;
  const newUrl = url.origin.replace(url.host, hostname) + request.url.substring(url.origin.length);
  if (FetchUtil.VERBOSE) console.log(`cloneRequestWithHostname: ${url} + ${hostname} = ${newUrl}`);
  const { method, headers } = request;
  const body = method === "GET" || method === "HEAD" ? void 0 : request.body;
  return new Request(newUrl, { method, headers, body });
}

// https://raw.githubusercontent.com/skymethod/denoflare/f414afa279f0ab095eb40505f51afa913adc2d7e/common/config.ts
function isTextBinding(binding) {
  return typeof binding.value === "string";
}
function isSecretBinding(binding) {
  return typeof binding.secret === "string";
}
function isKVNamespaceBinding(binding) {
  return typeof binding.kvNamespace === "string";
}
function isDONamespaceBinding(binding) {
  return typeof binding.doNamespace === "string";
}
function isR2BucketBinding(binding) {
  return typeof binding.bucketName === "string";
}
function isAnalyticsEngineBinding(binding) {
  return typeof binding.dataset === "string";
}
function isD1DatabaseBinding(binding) {
  return typeof binding.d1DatabaseUuid === "string";
}
function isQueueBinding(binding) {
  return typeof binding.queueName === "string";
}
function isSecretKeyBinding(binding) {
  return typeof binding.secretKey === "string";
}
function isSendEmailBinding(binding) {
  return typeof binding.sendEmailDestinationAddresses === "string";
}

// https://raw.githubusercontent.com/skymethod/denoflare/f414afa279f0ab095eb40505f51afa913adc2d7e/common/bytes.ts
var Bytes = class _Bytes {
  static EMPTY = new _Bytes(new Uint8Array(0));
  _bytes;
  length;
  constructor(bytes) {
    this._bytes = bytes;
    this.length = bytes.length;
  }
  array() {
    return this._bytes;
  }
  async sha1() {
    const hash = await cryptoSubtle().digest("SHA-1", this._bytes);
    return new _Bytes(new Uint8Array(hash));
  }
  concat(other) {
    const rt = new Uint8Array(this.length + other.length);
    rt.set(this._bytes);
    rt.set(other._bytes, this.length);
    return new _Bytes(rt);
  }
  async gitSha1Hex() {
    return (await _Bytes.ofUtf8(`blob ${this.length}\0`).concat(this).sha1()).hex();
  }
  async hmacSha1(key) {
    const cryptoKey = await cryptoSubtle().importKey("raw", key._bytes, { name: "HMAC", hash: "SHA-1" }, true, ["sign"]);
    const sig = await cryptoSubtle().sign("HMAC", cryptoKey, this._bytes);
    return new _Bytes(new Uint8Array(sig));
  }
  async sha256() {
    const hash = await cryptoSubtle().digest("SHA-256", this._bytes);
    return new _Bytes(new Uint8Array(hash));
  }
  async hmacSha256(key) {
    const cryptoKey = await cryptoSubtle().importKey("raw", key._bytes, { name: "HMAC", hash: "SHA-256" }, true, ["sign"]);
    const sig = await cryptoSubtle().sign("HMAC", cryptoKey, this._bytes);
    return new _Bytes(new Uint8Array(sig));
  }
  hex() {
    const a = Array.from(this._bytes);
    return a.map((b) => b.toString(16).padStart(2, "0")).join("");
  }
  static ofHex(hex) {
    if (hex === "") {
      return _Bytes.EMPTY;
    }
    return new _Bytes(new Uint8Array(hex.match(/.{1,2}/g).map((byte) => parseInt(byte, 16))));
  }
  utf8() {
    return new TextDecoder().decode(this._bytes);
  }
  static ofUtf8(str) {
    return new _Bytes(new TextEncoder().encode(str));
  }
  base64() {
    return base64Encode(this._bytes);
  }
  static ofBase64(base64, opts = { urlSafe: false }) {
    return new _Bytes(base64Decode(base64, opts.urlSafe));
  }
  static async ofStream(stream) {
    const chunks = [];
    for await (const chunk of stream) {
      chunks.push(chunk);
    }
    const len = chunks.reduce((prev, current) => prev + current.length, 0);
    const rt = new Uint8Array(len);
    let offset = 0;
    for (const chunk of chunks) {
      rt.set(chunk, offset);
      offset += chunk.length;
    }
    return new _Bytes(rt);
  }
  static formatSize(sizeInBytes) {
    const sign = sizeInBytes < 0 ? "-" : "";
    let size = Math.abs(sizeInBytes);
    if (size < 1024) return `${sign}${size}bytes`;
    size = size / 1024;
    if (size < 1024) return `${sign}${roundToOneDecimal(size)}kb`;
    size = size / 1024;
    if (size < 1024) return `${sign}${roundToOneDecimal(size)}mb`;
    size = size / 1024;
    return `${sign}${roundToOneDecimal(size)}gb`;
  }
};
function roundToOneDecimal(value) {
  return Math.round(value * 10) / 10;
}
function base64Encode(buf) {
  const pieces = new Array(buf.length);
  for (let i = 0; i < buf.length; i++) {
    pieces.push(String.fromCharCode(buf[i]));
  }
  return btoa(pieces.join(""));
}
function base64Decode(str, urlSafe) {
  if (urlSafe) str = str.replace(/_/g, "/").replace(/-/g, "+");
  str = atob(str);
  const length = str.length, buf = new ArrayBuffer(length), bufView = new Uint8Array(buf);
  for (let i = 0; i < length; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return bufView;
}
function cryptoSubtle() {
  return crypto.subtle;
}

// https://raw.githubusercontent.com/skymethod/denoflare/f414afa279f0ab095eb40505f51afa913adc2d7e/common/denoflare_response.ts
var DenoflareResponse = class _DenoflareResponse {
  _kind = "DenoflareResponse";
  get bodyInit() {
    return this._bodyInit;
  }
  _bodyInit;
  init;
  headers;
  status;
  statusText;
  webSocket;
  url;
  redirected;
  constructor(bodyInit, init) {
    this._bodyInit = bodyInit;
    this.init = init;
    this.headers = init && init.headers ? new Headers(init.headers) : new Headers();
    this.status = init && init.status !== void 0 ? init.status : 200;
    this.statusText = init && init.statusText !== void 0 ? init.statusText : "";
    this.webSocket = init?.webSocket;
    this.url = init?.url || "";
    this.redirected = init?.redirected || false;
  }
  // deno-lint-ignore no-explicit-any
  json() {
    if (typeof this.bodyInit === "string") {
      return Promise.resolve(JSON.parse(this.bodyInit));
    }
    throw new Error(`DenoflareResponse.json() bodyInit=${this.bodyInit}`);
  }
  text() {
    if (typeof this.bodyInit === "string") {
      return Promise.resolve(this.bodyInit);
    }
    if (typeof this.bodyInit === "object") {
      if (this.bodyInit instanceof ArrayBuffer) {
        return Promise.resolve(new TextDecoder().decode(this.bodyInit));
      }
    }
    throw new Error(`DenoflareResponse.text() bodyInit=${this.bodyInit}`);
  }
  async arrayBuffer() {
    if (this.bodyInit instanceof ReadableStream) {
      return (await Bytes.ofStream(this.bodyInit)).array().buffer;
    }
    throw new Error(`DenoflareResponse.arrayBuffer() bodyInit=${this.bodyInit}`);
  }
  get body() {
    if (this.bodyInit === void 0 || this.bodyInit === null) return null;
    if (this.bodyInit instanceof ArrayBuffer) {
      return new Blob([this.bodyInit]).stream();
    }
    throw new Error(`DenoflareResponse.body: bodyInit=${this.bodyInit}`);
  }
  clone() {
    if (this.bodyInit instanceof ReadableStream) {
      const [stream1, stream2] = this.bodyInit.tee();
      this._bodyInit = stream1;
      return new _DenoflareResponse(stream2, cloneInit(this.init));
    }
    return new _DenoflareResponse(cloneBodyInit(this.bodyInit), cloneInit(this.init));
  }
  get ok() {
    throw new Error(`DenoflareResponse.ok not implemented`);
  }
  get trailer() {
    throw new Error(`DenoflareResponse.trailer not implemented`);
  }
  get type() {
    throw new Error(`DenoflareResponse.type not implemented`);
  }
  get bodyUsed() {
    throw new Error(`DenoflareResponse.bodyUsed not implemented`);
  }
  get blob() {
    throw new Error(`DenoflareResponse.blob() not implemented`);
  }
  get formData() {
    throw new Error(`DenoflareResponse.formData() not implemented`);
  }
  //
  toRealResponse() {
    return new _Response(this.bodyInit, this.init);
  }
  // deno-lint-ignore no-explicit-any
  static is(obj) {
    return typeof obj === "object" && obj._kind === "DenoflareResponse";
  }
};
var _Response = Response;
function cloneBodyInit(bodyInit) {
  if (bodyInit == void 0 || bodyInit === null || typeof bodyInit === "string") return bodyInit;
  if (typeof bodyInit === "object") {
    if (bodyInit instanceof ArrayBuffer) {
      return bodyInit.slice(0);
    }
  }
  throw new Error(`cloneBodyInit(); bodyInit=${typeof bodyInit} ${bodyInit}`);
}
function cloneInit(init) {
  if (init === void 0) return init;
  if (init.webSocket) throw new Error(`cloneInit: Response with a websocket cannot be cloned`);
  const { status, statusText, url, redirected } = init;
  const headers = cloneHeadersInit(init.headers);
  return { headers, status, statusText, url, redirected };
}
function cloneHeadersInit(headers) {
  if (headers === void 0) return headers;
  if (headers instanceof Headers) {
    return new Headers(headers);
  }
  return JSON.parse(JSON.stringify(headers));
}

// https://raw.githubusercontent.com/skymethod/denoflare/f414afa279f0ab095eb40505f51afa913adc2d7e/common/cloudflare_workers_runtime.ts
function defineModuleGlobals(globalCachesProvider, webSocketPairProvider) {
  defineGlobalCaches(globalCachesProvider);
  defineGlobalWebsocketPair(webSocketPairProvider);
  redefineGlobalResponse();
  patchGlobalRequest();
}
async function applyWorkerEnv(target, bindings, kvNamespaceProvider, doNamespaceProvider, r2BucketProvider, analyticsEngineProvider, d1DatabaseProvider, secretKeyProvider, emailSenderProvider, queueProvider) {
  for (const [name, binding] of Object.entries(bindings)) {
    target[name] = await computeBindingValue(binding, kvNamespaceProvider, doNamespaceProvider, r2BucketProvider, analyticsEngineProvider, d1DatabaseProvider, secretKeyProvider, emailSenderProvider, queueProvider);
  }
}
async function defineScriptGlobals(bindings, globalCachesProvider, kvNamespaceProvider, doNamespaceProvider, r2BucketProvider, analyticsEngineProvider, d1DatabaseProvider, secretKeyProvider, emailSenderProvider, queueProvider) {
  await applyWorkerEnv(globalThisAsAny(), bindings, kvNamespaceProvider, doNamespaceProvider, r2BucketProvider, analyticsEngineProvider, d1DatabaseProvider, secretKeyProvider, emailSenderProvider, queueProvider);
  defineGlobalCaches(globalCachesProvider);
  redefineGlobalResponse();
  patchGlobalRequest();
}
function defineGlobalCaches(globalCachesProvider) {
  delete globalThisAsAny().caches;
  globalThisAsAny().caches = globalCachesProvider();
}
function redefineGlobalResponse() {
  globalThisAsAny()["Response"] = DenoflareResponse;
}
var _clone = Request.prototype.clone;
function patchGlobalRequest() {
  Request.prototype.clone = function() {
    const rt = _clone.bind(this)();
    rt.cf = structuredClone(this.cf);
    return rt;
  };
}
function defineGlobalWebsocketPair(webSocketPairProvider) {
  DenoflareWebSocketPair.provider = webSocketPairProvider;
  globalThisAsAny()["WebSocketPair"] = DenoflareWebSocketPair;
}
function globalThisAsAny() {
  return globalThis;
}
async function computeBindingValue(binding, kvNamespaceProvider, doNamespaceProvider, r2BucketProvider, analyticsEngineProvider, d1DatabaseProvider, secretKeyProvider, emailSenderProvider, queueProvider) {
  if (isTextBinding(binding)) return binding.value;
  if (isSecretBinding(binding)) return binding.secret;
  if (isKVNamespaceBinding(binding)) return kvNamespaceProvider(binding.kvNamespace);
  if (isDONamespaceBinding(binding)) return doNamespaceProvider(binding.doNamespace);
  if (isR2BucketBinding(binding)) return r2BucketProvider(binding.bucketName);
  if (isAnalyticsEngineBinding(binding)) return analyticsEngineProvider(binding.dataset);
  if (isD1DatabaseBinding(binding)) return d1DatabaseProvider(binding.d1DatabaseUuid);
  if (isSecretKeyBinding(binding)) return await secretKeyProvider(binding.secretKey);
  if (isSendEmailBinding(binding)) return emailSenderProvider(binding.sendEmailDestinationAddresses);
  if (isQueueBinding(binding)) return queueProvider(binding.queueName);
  throw new Error(`TODO implement binding ${JSON.stringify(binding)}`);
}
var DenoflareWebSocketPair = class _DenoflareWebSocketPair {
  static provider = () => {
    throw new Error(`DenoflareWebSocketPair: no provider set`);
  };
  0;
  // client, returned in the ResponseInit
  1;
  // server, accept(), addEventListener(), send() and close()
  constructor() {
    const { server, client } = _DenoflareWebSocketPair.provider();
    this["0"] = client;
    this["1"] = server;
  }
};

// https://raw.githubusercontent.com/skymethod/denoflare/f414afa279f0ab095eb40505f51afa913adc2d7e/common/module_worker_execution.ts
var ModuleWorkerExecution = class _ModuleWorkerExecution {
  static VERBOSE = false;
  worker;
  constructor(worker) {
    this.worker = worker;
  }
  static async create(scriptPath, bindings, callbacks) {
    const { globalCachesProvider, webSocketPairProvider, onModuleWorkerInfo, kvNamespaceProvider, doNamespaceProvider, r2BucketProvider, analyticsEngineProvider, d1DatabaseProvider, secretKeyProvider, emailSenderProvider, queueProvider } = callbacks;
    defineModuleGlobals(globalCachesProvider, webSocketPairProvider);
    const module = await import(scriptPath);
    if (_ModuleWorkerExecution.VERBOSE) consoleLog("ModuleWorkerExecution: module", module);
    const moduleWorkerExportedFunctions = {};
    for (const [name, value] of Object.entries(module)) {
      if (typeof value === "function") {
        moduleWorkerExportedFunctions[name] = value;
      }
    }
    const moduleWorkerEnv = {};
    if (onModuleWorkerInfo) onModuleWorkerInfo({ moduleWorkerExportedFunctions, moduleWorkerEnv });
    await applyWorkerEnv(moduleWorkerEnv, bindings, kvNamespaceProvider, doNamespaceProvider, r2BucketProvider, analyticsEngineProvider, d1DatabaseProvider, secretKeyProvider, emailSenderProvider, queueProvider);
    if (module === void 0) throw new Error("Bad module: undefined");
    if (module.default === void 0) throw new Error("Bad module.default: undefined");
    if (typeof module.default.fetch !== "function") throw new Error(`Bad module.default.fetch: ${typeof module.default.fetch}`);
    if (module.default.alarm !== void 0 && typeof module.default.alarm !== "function") throw new Error(`Bad module.default.alarm: ${typeof module.default.alarm}`);
    return new _ModuleWorkerExecution({ fetch: module.default.fetch, alarm: module.default.alarm, moduleWorkerEnv });
  }
  async fetch(request) {
    return await this.worker.fetch(request, this.worker.moduleWorkerEnv, new DefaultModuleWorkerContext());
  }
};
var DefaultModuleWorkerContext = class {
  passThroughOnException() {
  }
  waitUntil(promise) {
    promise.then(() => {
    }, (e) => consoleWarn(e));
  }
};

// https://raw.githubusercontent.com/skymethod/denoflare/f414afa279f0ab095eb40505f51afa913adc2d7e/common/script_worker_execution.ts
var ScriptWorkerExecution = class _ScriptWorkerExecution {
  worker;
  constructor(worker) {
    this.worker = worker;
  }
  static async create(scriptPath, bindings, callbacks) {
    const { globalCachesProvider, kvNamespaceProvider, doNamespaceProvider, r2BucketProvider, analyticsEngineProvider, d1DatabaseProvider, secretKeyProvider, emailSenderProvider, queueProvider } = callbacks;
    await defineScriptGlobals(bindings, globalCachesProvider, kvNamespaceProvider, doNamespaceProvider, r2BucketProvider, analyticsEngineProvider, d1DatabaseProvider, secretKeyProvider, emailSenderProvider, queueProvider);
    let fetchListener;
    const addEventListener = (type, listener) => {
      consoleLog(`script: addEventListener type=${type}`);
      if (type === "fetch") {
        fetchListener = listener;
      }
    };
    self.addEventListener = addEventListener;
    await import(scriptPath);
    if (fetchListener === void 0) throw new Error(`Script did not add a fetch listener`);
    return new _ScriptWorkerExecution({ fetchListener });
  }
  async fetch(request) {
    const e = new FetchEvent(request);
    await this.worker.fetchListener(e);
    if (e.responseFn === void 0) throw new Error(`Event handler did not set a response using respondWith`);
    const response = await e.responseFn;
    return response;
  }
};
var FetchEvent = class extends Event {
  request;
  responseFn;
  constructor(request) {
    super("fetch");
    this.request = request;
  }
  waitUntil(promise) {
    promise.then(() => {
    }, (e) => consoleWarn(e));
  }
  respondWith(responseFn) {
    if (this.responseFn) throw new Error(`respondWith: already called`);
    this.responseFn = responseFn;
  }
};

// https://raw.githubusercontent.com/skymethod/denoflare/f414afa279f0ab095eb40505f51afa913adc2d7e/common/uuid_v4.ts
function generateUuid() {
  const cryptoAsAny = crypto;
  if (typeof cryptoAsAny.randomUUID === "function") {
    return cryptoAsAny.randomUUID();
  }
  const rnds = crypto.getRandomValues(new Uint8Array(16));
  rnds[6] = rnds[6] & 15 | 64;
  rnds[8] = rnds[8] & 63 | 128;
  return bytesToUuid(rnds);
}
function bytesToUuid(bytes) {
  const bits = [...bytes].map((bit) => {
    const s = bit.toString(16);
    return bit < 16 ? "0" + s : s;
  });
  return [
    ...bits.slice(0, 4),
    "-",
    ...bits.slice(4, 6),
    "-",
    ...bits.slice(6, 8),
    "-",
    ...bits.slice(8, 10),
    "-",
    ...bits.slice(10, 16)
  ].join("");
}

// https://raw.githubusercontent.com/skymethod/denoflare/f414afa279f0ab095eb40505f51afa913adc2d7e/common/worker_execution.ts
var WorkerExecution = class _WorkerExecution {
  callbacks;
  worker;
  constructor(callbacks, worker) {
    this.callbacks = callbacks;
    this.worker = worker;
  }
  static async start(scriptPathOrUrl, scriptType, bindings, callbacks) {
    const worker = scriptType === "module" ? await ModuleWorkerExecution.create(scriptPathOrUrl, bindings, callbacks) : await ScriptWorkerExecution.create(scriptPathOrUrl, bindings, callbacks);
    return new _WorkerExecution(callbacks, worker);
  }
  async fetch(request, opts) {
    consoleLog(`${request.method} ${request.url}`);
    const cf = this.callbacks.incomingRequestCfPropertiesProvider();
    const req = makeIncomingRequestCf(request, cf, opts);
    return await this.worker.fetch(req);
  }
};
function makeIncomingRequestCf(request, cf, opts) {
  const { cfConnectingIp, hostname } = opts;
  if (hostname) request = cloneRequestWithHostname(request, hostname);
  if (request.method === "GET" || request.method === "HEAD") {
    const { method, headers, url } = request;
    request = new Request(url, { method, headers });
  }
  const req = new Request(request, { headers: [...request.headers, ["cf-connecting-ip", cfConnectingIp], ["cf-ray", generateNewCfRay()]] });
  req.cf = cf;
  return req;
}
function generateNewCfRay() {
  const tokens = generateUuid().split("-");
  return tokens[3] + tokens[4];
}

// https://raw.githubusercontent.com/skymethod/denoflare/f414afa279f0ab095eb40505f51afa913adc2d7e/cli/versions.ts
function versionCompare(lhs, rhs) {
  if (lhs === rhs) return 0;
  const lhsTokens = lhs.split(".");
  const rhsTokens = rhs.split(".");
  for (let i = 0; i < Math.max(lhsTokens.length, rhsTokens.length); i++) {
    const lhsNum = parseInt(lhsTokens[i] ?? "0");
    const rhsNum = parseInt(rhsTokens[i] ?? "0");
    if (lhsNum < rhsNum) return -1;
    if (lhsNum > rhsNum) return 1;
  }
  return 0;
}

// https://raw.githubusercontent.com/skymethod/denoflare/f414afa279f0ab095eb40505f51afa913adc2d7e/common/constants.ts
var Constants = class {
  static MAX_CONTENT_LENGTH_TO_PACK_OVER_RPC = 1024 * 1024 * 5;
  // bypass read-body-chunk for fetch responses with defined content-length under this limit
};

// https://raw.githubusercontent.com/skymethod/denoflare/f414afa279f0ab095eb40505f51afa913adc2d7e/common/rpc_fetch.ts
function makeFetchOverRpc(channel, denoVersion, bodies, webSocketResolver) {
  return async (info, init) => {
    const data = packRequest(info, init, bodies);
    return await channel.sendRequest("fetch", data, (responseData) => unpackResponse(responseData, makeBodyResolverOverRpc(channel, denoVersion), webSocketResolver));
  };
}
function makeBodyResolverOverRpc(channel, denoVersion) {
  const shouldApplyEventLookWorkaround = versionCompare(denoVersion, "1.41.2") < 0;
  return (bodyId) => new ReadableStream({
    start(_controller) {
    },
    async pull(controller) {
      const { value, done } = await channel.sendRequest("read-body-chunk", { bodyId }, (responseData) => {
        return responseData;
      });
      const finish = () => {
        if (value !== void 0) controller.enqueue(value);
        if (done) try {
          controller.close();
        } catch (e) {
          console.warn(`Ignoring error closing rpc body stream: ${e.stack}`);
        }
      };
      if (shouldApplyEventLookWorkaround) {
        setTimeout(finish, 0);
      } else {
        finish();
      }
    },
    cancel(reason) {
      consoleLog(`RpcBodyResolver(${bodyId}): cancel reason=${reason}`);
    }
  });
}
function addRequestHandlerForReadBodyChunk(channel, bodies) {
  channel.addRequestHandler("read-body-chunk", async (requestData) => {
    const { bodyId } = requestData;
    const { value, done } = await bodies.readBodyChunk(bodyId);
    return { data: { value, done }, transfer: value ? [value.buffer] : [] };
  });
}
async function packResponse(response, bodies, webSocketPacker, overrideContentType) {
  const { status, statusText, url, redirected } = response;
  const headers = [...response.headers.entries()];
  if (overrideContentType) {
    const i = headers.findIndex((v) => v[0].toLowerCase() === "content-type");
    if (i > -1) {
      headers.splice(i, 1);
    }
    headers.push(["content-type", overrideContentType]);
  }
  if (DenoflareResponse.is(response)) {
    const webSocketId2 = response.init?.webSocket ? webSocketPacker(response.init?.webSocket) : void 0;
    if (typeof response.bodyInit === "string") {
      const bodyText = response.bodyInit;
      return { status, statusText, headers, bodyId: void 0, bodyText, bodyBytes: void 0, bodyNull: false, webSocketId: webSocketId2, url, redirected };
    } else if (response.bodyInit instanceof Uint8Array) {
      const bodyBytes = response.bodyInit;
      return { status, statusText, headers, bodyId: void 0, bodyText: void 0, bodyBytes, bodyNull: false, webSocketId: webSocketId2, url, redirected };
    } else if (response.bodyInit instanceof Blob) {
      const bodyBytes = new Uint8Array(await response.bodyInit.arrayBuffer());
      return { status, statusText, headers, bodyId: void 0, bodyText: void 0, bodyBytes, bodyNull: false, webSocketId: webSocketId2, url, redirected };
    } else if (response.bodyInit instanceof ReadableStream) {
      const bodyId2 = bodies.computeBodyId(response.bodyInit);
      return { status, statusText, headers, bodyId: bodyId2, bodyText: void 0, bodyBytes: void 0, bodyNull: false, webSocketId: webSocketId2, url, redirected };
    } else if (response.bodyInit instanceof ArrayBuffer) {
      const bodyBytes = new Uint8Array(new Uint8Array(response.bodyInit));
      return { status, statusText, headers, bodyId: void 0, bodyText: void 0, bodyBytes, bodyNull: false, webSocketId: webSocketId2, url, redirected };
    } else if (response.bodyInit === null || response.bodyInit === void 0) {
      return { status, statusText, headers, bodyId: void 0, bodyText: void 0, bodyBytes: void 0, bodyNull: true, webSocketId: webSocketId2, url, redirected };
    } else {
      throw new Error(`packResponse: DenoflareResponse bodyInit=${response.bodyInit}`);
    }
  }
  const webSocketId = void 0;
  const contentLength = parseInt(response.headers.get("content-length") || "-1");
  if (contentLength > -1 && contentLength <= Constants.MAX_CONTENT_LENGTH_TO_PACK_OVER_RPC) {
    const bodyBytes = new Uint8Array(await response.arrayBuffer());
    return { status, statusText, headers, bodyId: void 0, bodyText: void 0, bodyBytes, bodyNull: false, webSocketId, url, redirected };
  }
  const bodyId = bodies.computeBodyId(response.body);
  return { status, statusText, headers, bodyId, bodyText: void 0, bodyBytes: void 0, bodyNull: false, webSocketId, url, redirected };
}
var _Response2 = Response;
function unpackResponse(packed, bodyResolver, webSocketResolver) {
  const { status, statusText, bodyId, bodyText, bodyBytes, bodyNull, webSocketId, url, redirected } = packed;
  const headers = new Headers(packed.headers);
  const body = bodyNull ? null : bodyText !== void 0 ? bodyText : bodyBytes !== void 0 ? bodyBytes : bodyId === void 0 ? void 0 : bodyResolver(bodyId);
  if (status === 101) {
    if (!webSocketId) throw new Error(`unpackResponse: 101 responses must have a webSocketId`);
    const webSocket = webSocketResolver(webSocketId);
    return new DenoflareResponse(body, { status, statusText, headers, webSocket, url, redirected });
  }
  const rt = new _Response2(body, { status, statusText, headers });
  Object.defineProperty(rt, "url", { value: url });
  Object.defineProperty(rt, "redirected", { value: redirected });
  return rt;
}
function packRequest(info, init, bodies) {
  if (info instanceof URL) throw new Error(`Calling fetch(URL) is against the spec`);
  if (typeof info === "object" && init === void 0) {
    const { method, url, redirect } = info;
    const headers = [...info.headers.entries()];
    const bodyId = method === "GET" || method === "HEAD" ? void 0 : bodies.computeBodyId(info.body);
    return { method, url, headers, bodyId, bodyText: void 0, bodyBytes: void 0, bodyNull: false, redirect };
  } else if (typeof info === "string") {
    const url = info;
    let method = "GET";
    let headers = [];
    let redirect;
    let bodyId;
    let bodyText;
    let bodyBytes;
    let bodyNull = false;
    if (init !== void 0) {
      if (init.method !== void 0) method = init.method;
      if (init.headers !== void 0) headers = [...new Headers(init.headers).entries()];
      if (init.body !== void 0) {
        if (typeof init.body === "string") {
          bodyText = init.body;
        } else if (init.body instanceof Uint8Array) {
          bodyBytes = init.body;
        } else if (init.body instanceof ReadableStream) {
          bodyId = bodies.computeBodyId(init.body);
        } else if (init.body instanceof ArrayBuffer) {
          bodyBytes = new Uint8Array(new Uint8Array(init.body));
        } else if (init.body === null) {
          bodyNull = true;
        } else if (init.body instanceof FormData) {
          bodyText = new URLSearchParams(init.body).toString();
          headers = headers.filter((v) => v[0] !== "content-type");
          headers.push(["content-type", "application/x-www-form-urlencoded"]);
        } else {
          throw new Error(`packRequest: init.body`);
        }
      }
      if (init.cache !== void 0) throw new Error(`packRequest: init.cache`);
      if (init.credentials !== void 0) throw new Error(`packRequest: init.credentials`);
      if (init.integrity !== void 0) throw new Error(`packRequest: init.integrity`);
      if (init.keepalive !== void 0) throw new Error(`packRequest: init.keepalive`);
      if (init.mode !== void 0) throw new Error(`packRequest: init.mode`);
      if (init.referrer !== void 0) throw new Error(`packRequest: init.referrer`);
      if (init.referrerPolicy !== void 0) throw new Error(`packRequest: init.referrerPolicy`);
      if (init.signal !== void 0) throw new Error(`packRequest: init.signal`);
      if (init.window !== void 0) throw new Error(`packRequest: init.window`);
      redirect = init.redirect;
    }
    return { method, url, headers, bodyId, bodyText, bodyBytes, bodyNull, redirect };
  }
  throw new Error(`packRequest: implement info=${info} ${typeof info} init=${init}`);
}
function unpackRequest(packedRequest, bodyResolver) {
  const { url, method, bodyId, bodyText, bodyBytes, bodyNull, redirect } = packedRequest;
  const headers = new Headers(packedRequest.headers);
  const body = bodyNull ? null : bodyText !== void 0 ? bodyText : bodyBytes !== void 0 ? bodyBytes : bodyId === void 0 ? void 0 : bodyResolver(bodyId);
  return new Request(url, { method, headers, body, redirect });
}
var Bodies = class {
  bodies = /* @__PURE__ */ new Map();
  readers = /* @__PURE__ */ new Map();
  nextBodyId = 1;
  computeBodyId(body) {
    if (!body) return void 0;
    const bodyId = this.nextBodyId++;
    this.bodies.set(bodyId, body);
    return bodyId;
  }
  async readBodyChunk(bodyId) {
    let reader = this.readers.get(bodyId);
    if (reader === void 0) {
      const body = this.bodies.get(bodyId);
      if (!body) throw new Error(`Bad bodyId: ${bodyId}`);
      reader = body.getReader();
      this.readers.set(bodyId, reader);
    }
    const result = await reader.read();
    if (result.done) {
      this.readers.delete(bodyId);
      this.bodies.delete(bodyId);
    }
    return result;
  }
};

// https://raw.githubusercontent.com/skymethod/denoflare/f414afa279f0ab095eb40505f51afa913adc2d7e/common/incoming_request_cf_properties.ts
function makeIncomingRequestCfProperties() {
  return { colo: "DNO", asn: 13335, city: "Cleveland" };
}

// https://raw.githubusercontent.com/skymethod/denoflare/f414afa279f0ab095eb40505f51afa913adc2d7e/common/unimplemented_cloudflare_stubs.ts
var UnimplementedDurableObjectNamespace = class {
  doNamespace;
  constructor(doNamespace) {
    this.doNamespace = doNamespace;
  }
  newUniqueId(_opts) {
    throw new Error(`UnimplementedDurableObjectNamespace.newUniqueId not implemented.`);
  }
  idFromName(_name) {
    throw new Error(`UnimplementedDurableObjectNamespace.idFromName not implemented.`);
  }
  idFromString(_hexStr) {
    throw new Error(`UnimplementedDurableObjectNamespace.idFromString not implemented.`);
  }
  get(_id) {
    throw new Error(`UnimplementedDurableObjectNamespace.get not implemented.`);
  }
};

// https://raw.githubusercontent.com/skymethod/denoflare/f414afa279f0ab095eb40505f51afa913adc2d7e/common/mutex.ts
var Mutex = class {
  mutex = Promise.resolve();
  lock() {
    let begin = () => {
    };
    this.mutex = this.mutex.then(() => {
      return new Promise(begin);
    });
    return new Promise((res) => {
      begin = res;
    });
  }
  async dispatch(fn) {
    const unlock = await this.lock();
    try {
      return await Promise.resolve(fn());
    } finally {
      unlock();
    }
  }
};

// https://raw.githubusercontent.com/skymethod/denoflare/f414afa279f0ab095eb40505f51afa913adc2d7e/common/check.ts
function checkMatches(name, value, pattern) {
  if (!pattern.test(value)) throw new Error(`Bad ${name}: ${value}`);
  return value;
}
function isStringArray(obj) {
  return Array.isArray(obj) && obj.every((v) => typeof v === "string");
}
function isStringRecord(obj) {
  return typeof obj === "object" && obj !== null && !Array.isArray(obj) && obj.constructor === Object;
}

// https://raw.githubusercontent.com/skymethod/denoflare/f414afa279f0ab095eb40505f51afa913adc2d7e/common/storage/in_memory_durable_object_storage.ts
var InMemoryDurableObjectStorage = class _InMemoryDurableObjectStorage {
  static VERBOSE = false;
  // no semantic support for transactions, although they will work in simple cases
  sortedKeys = [];
  values = /* @__PURE__ */ new Map();
  //
  async export(writable) {
    const writer = writable.getWriter();
    const encoder = new TextEncoder();
    await writer.write(encoder.encode("[\n"));
    let exported = 0;
    for (const key of this.sortedKeys) {
      const value = this.values.get(key);
      await writer.write(encoder.encode(`  ${exported++ > 0 ? "," : ""}${JSON.stringify([key, value])}
`));
    }
    await writer.write(encoder.encode("]\n"));
    await writer.close();
    return exported;
  }
  async import(readable) {
    const arr = JSON.parse((await Bytes.ofStream(readable)).utf8());
    if (!Array.isArray(arr)) throw new Error();
    const keys = new Set(this.sortedKeys);
    for (const item of arr) {
      if (!Array.isArray(item) || item.length !== 2 || typeof item[0] !== "string") throw new Error(JSON.stringify(item));
      const [key, value] = item;
      if (!keys.has(key)) {
        this.sortedKeys.push(key);
      }
      this.values.set(key, value);
    }
    this.sortedKeys.sort();
    return arr.length;
  }
  //
  async transaction(closure) {
    if (_InMemoryDurableObjectStorage.VERBOSE) console.log(`InMemoryDurableObjectStorage: transaction()`);
    const txn = new InMemoryDurableObjectStorageTransaction(this);
    return await Promise.resolve(closure(txn));
  }
  sync() {
    if (_InMemoryDurableObjectStorage.VERBOSE) console.log(`InMemoryDurableObjectStorage: sync()`);
    return Promise.resolve();
  }
  deleteAll() {
    if (_InMemoryDurableObjectStorage.VERBOSE) console.log(`InMemoryDurableObjectStorage: deleteAll()`);
    this.sortedKeys.splice(0);
    this.values.clear();
    return Promise.resolve();
  }
  get(keyOrKeys, opts) {
    if (_InMemoryDurableObjectStorage.VERBOSE) console.log(`InMemoryDurableObjectStorage: get(${JSON.stringify({ keyOrKeys, opts })})`);
    return this._get(keyOrKeys, opts);
  }
  _get(keyOrKeys, opts) {
    if (typeof keyOrKeys === "string" && Object.keys(opts || {}).length === 0) {
      const key = keyOrKeys;
      return Promise.resolve(structuredClone(this.values.get(key)));
    }
    if (isStringArray(keyOrKeys) && Object.keys(opts || {}).length === 0) {
      const keys = keyOrKeys;
      const rt = /* @__PURE__ */ new Map();
      for (const key of keys) {
        const value = this.values.get(key);
        if (value !== void 0) {
          rt.set(key, structuredClone(value));
        }
      }
      return Promise.resolve(rt);
    }
    throw new Error(`InMemoryDurableObjectStorage.get not implemented`);
  }
  put(arg1, arg2, arg3) {
    if (_InMemoryDurableObjectStorage.VERBOSE) console.log(`InMemoryDurableObjectStorage: put(${JSON.stringify({ arg1, arg2, arg3 })})`);
    return this._put(arg1, arg2, arg3);
  }
  _put(arg1, arg2, arg3) {
    if (typeof arg1 === "object" && arg2 === void 0 && arg3 === void 0) {
      const entries = arg1;
      let sortedKeysChanged = false;
      for (const [key, value] of Object.entries(entries)) {
        if (!this.sortedKeys.includes(key)) {
          this.sortedKeys.push(key);
          sortedKeysChanged = true;
        }
        const val = value;
        this.values.set(key, structuredClone(val));
      }
      if (sortedKeysChanged) {
        this.sortedKeys.sort();
      }
      return Promise.resolve();
    }
    if (typeof arg1 === "string" && arg2 !== void 0 && arg3 === void 0) {
      const key = arg1;
      const val = arg2;
      let sortedKeysChanged = false;
      if (!this.sortedKeys.includes(key)) {
        this.sortedKeys.push(key);
        sortedKeysChanged = true;
      }
      this.values.set(key, structuredClone(val));
      if (sortedKeysChanged) {
        this.sortedKeys.sort();
      }
      return Promise.resolve();
    }
    throw new Error(`InMemoryDurableObjectStorage.put not implemented arg1=${arg1}, arg2=${arg2}, arg3=${arg3}`);
  }
  delete(keyOrKeys, opts) {
    if (_InMemoryDurableObjectStorage.VERBOSE) console.log(`InMemoryDurableObjectStorage: delete(${JSON.stringify({ keyOrKeys, opts })})`);
    return this._delete(keyOrKeys, opts);
  }
  _delete(keyOrKeys, opts) {
    if (typeof keyOrKeys === "string" && Object.keys(opts || {}).length === 0) {
      const key = keyOrKeys;
      const i = this.sortedKeys.indexOf(key);
      if (i < 0) return Promise.resolve(false);
      this.sortedKeys.splice(i, 1);
      this.values.delete(key);
      return Promise.resolve(true);
    } else if (isStringArray(keyOrKeys) && Object.keys(opts || {}).length === 0) {
      const keys = keyOrKeys;
      let rt = 0;
      for (const key of keys) {
        const i = this.sortedKeys.indexOf(key);
        if (i > -1) {
          this.sortedKeys.splice(i, 1);
          this.values.delete(key);
          rt++;
        }
      }
      return Promise.resolve(rt);
    }
    throw new Error(`InMemoryDurableObjectStorage.delete not implemented: ${typeof keyOrKeys}, ${opts}`);
  }
  list(options = {}) {
    if (_InMemoryDurableObjectStorage.VERBOSE) console.log(`InMemoryDurableObjectStorage: list(${JSON.stringify({ options })})`);
    const { start, startAfter, end, prefix, limit, reverse, allowConcurrency, noCache } = options;
    for (const [name, value] of Object.entries({ allowConcurrency, noCache })) {
      if (value !== void 0) throw new Error(`InMemoryDurableObjectStorage.list(${name}) not implemented: ${JSON.stringify(options)}`);
    }
    const { sortedKeys, values } = this;
    const rt = /* @__PURE__ */ new Map();
    let orderedKeys = sortedKeys;
    if (reverse) orderedKeys = [...orderedKeys].reverse();
    for (const key of orderedKeys) {
      if (limit !== void 0 && rt.size >= limit) return Promise.resolve(rt);
      if (prefix !== void 0 && !key.startsWith(prefix)) continue;
      if (typeof start === "string" && (reverse ? key > start : key < start)) continue;
      if (typeof startAfter === "string" && (reverse ? key >= startAfter : key <= startAfter)) continue;
      if (typeof end === "string" && (reverse ? key <= end : key >= end)) break;
      const value = structuredClone(values.get(key));
      rt.set(key, value);
    }
    return Promise.resolve(rt);
  }
  getAlarm(options) {
    throw new Error(`InMemoryDurableObjectStorage.getAlarm not implemented options=${JSON.stringify(options)}`);
  }
  setAlarm(scheduledTime, options) {
    throw new Error(`InMemoryDurableObjectStorage.setAlarm not implemented scheduledTime=${scheduledTime} options=${JSON.stringify(options)}`);
  }
  deleteAlarm(options) {
    throw new Error(`InMemoryDurableObjectStorage.deleteAlarm not implemented options=${JSON.stringify(options)}`);
  }
  getBookmarkForTime(timestamp) {
    throw new Error(`InMemoryDurableObjectStorage.getBookmarkForTime(${JSON.stringify({ timestamp })}) not implemented`);
  }
  getCurrentBookmark() {
    throw new Error(`InMemoryDurableObjectStorage.getCurrentBookmark() not implemented`);
  }
  onNextSessionRestoreBookmark(bookmark) {
    throw new Error(`InMemoryDurableObjectStorage.onNextSessionRestoreBookmark(${JSON.stringify({ bookmark })}) not implemented`);
  }
  transactionSync(_closure) {
    throw new Error(`InMemoryDurableObjectStorage.transactionSync() not implemented`);
  }
  get sql() {
    throw new Error(`InMemoryDurableObjectStorage.sql not implemented`);
  }
};
var InMemoryDurableObjectStorageTransaction = class {
  storage;
  constructor(storage) {
    this.storage = storage;
  }
  rollback() {
    throw new Error(`InMemoryDurableObjectStorageTransaction.rollback not implemented`);
  }
  deleteAll() {
    return this.storage.deleteAll();
  }
  get(keyOrKeys, opts) {
    return this.storage._get(keyOrKeys, opts);
  }
  put(arg1, arg2, arg3) {
    return this.storage._put(arg1, arg2, arg3);
  }
  delete(keyOrKeys, opts) {
    return this.storage._delete(keyOrKeys, opts);
  }
  list(options = {}) {
    return this.storage.list(options);
  }
  getAlarm(options) {
    return this.storage.getAlarm(options);
  }
  setAlarm(scheduledTime, options) {
    return this.storage.setAlarm(scheduledTime, options);
  }
  deleteAlarm(options) {
    return this.storage.deleteAlarm(options);
  }
};

// https://raw.githubusercontent.com/skymethod/denoflare/f414afa279f0ab095eb40505f51afa913adc2d7e/common/sha1.ts
var HEX_CHARS = "0123456789abcdef".split("");
var EXTRA = [-2147483648, 8388608, 32768, 128];
var SHIFT = [24, 16, 8, 0];
var blocks = [];
var Sha1 = class {
  #blocks;
  #block;
  #start;
  #bytes;
  #hBytes;
  #finalized;
  #hashed;
  #h0 = 1732584193;
  #h1 = 4023233417;
  #h2 = 2562383102;
  #h3 = 271733878;
  #h4 = 3285377520;
  #lastByteIndex = 0;
  constructor(sharedMemory = false) {
    this.init(sharedMemory);
  }
  init(sharedMemory) {
    if (sharedMemory) {
      blocks[0] = blocks[16] = blocks[1] = blocks[2] = blocks[3] = blocks[4] = blocks[5] = blocks[6] = blocks[7] = blocks[8] = blocks[9] = blocks[10] = blocks[11] = blocks[12] = blocks[13] = blocks[14] = blocks[15] = 0;
      this.#blocks = blocks;
    } else {
      this.#blocks = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    }
    this.#h0 = 1732584193;
    this.#h1 = 4023233417;
    this.#h2 = 2562383102;
    this.#h3 = 271733878;
    this.#h4 = 3285377520;
    this.#block = this.#start = this.#bytes = this.#hBytes = 0;
    this.#finalized = this.#hashed = false;
  }
  update(message) {
    if (this.#finalized) {
      return this;
    }
    let msg;
    if (message instanceof ArrayBuffer) {
      msg = new Uint8Array(message);
    } else {
      msg = message;
    }
    let index = 0;
    const length = msg.length;
    const blocks2 = this.#blocks;
    while (index < length) {
      let i;
      if (this.#hashed) {
        this.#hashed = false;
        blocks2[0] = this.#block;
        blocks2[16] = blocks2[1] = blocks2[2] = blocks2[3] = blocks2[4] = blocks2[5] = blocks2[6] = blocks2[7] = blocks2[8] = blocks2[9] = blocks2[10] = blocks2[11] = blocks2[12] = blocks2[13] = blocks2[14] = blocks2[15] = 0;
      }
      if (typeof msg !== "string") {
        for (i = this.#start; index < length && i < 64; ++index) {
          blocks2[i >> 2] |= msg[index] << SHIFT[i++ & 3];
        }
      } else {
        for (i = this.#start; index < length && i < 64; ++index) {
          let code = msg.charCodeAt(index);
          if (code < 128) {
            blocks2[i >> 2] |= code << SHIFT[i++ & 3];
          } else if (code < 2048) {
            blocks2[i >> 2] |= (192 | code >> 6) << SHIFT[i++ & 3];
            blocks2[i >> 2] |= (128 | code & 63) << SHIFT[i++ & 3];
          } else if (code < 55296 || code >= 57344) {
            blocks2[i >> 2] |= (224 | code >> 12) << SHIFT[i++ & 3];
            blocks2[i >> 2] |= (128 | code >> 6 & 63) << SHIFT[i++ & 3];
            blocks2[i >> 2] |= (128 | code & 63) << SHIFT[i++ & 3];
          } else {
            code = 65536 + ((code & 1023) << 10 | msg.charCodeAt(++index) & 1023);
            blocks2[i >> 2] |= (240 | code >> 18) << SHIFT[i++ & 3];
            blocks2[i >> 2] |= (128 | code >> 12 & 63) << SHIFT[i++ & 3];
            blocks2[i >> 2] |= (128 | code >> 6 & 63) << SHIFT[i++ & 3];
            blocks2[i >> 2] |= (128 | code & 63) << SHIFT[i++ & 3];
          }
        }
      }
      this.#lastByteIndex = i;
      this.#bytes += i - this.#start;
      if (i >= 64) {
        this.#block = blocks2[16];
        this.#start = i - 64;
        this.hash();
        this.#hashed = true;
      } else {
        this.#start = i;
      }
    }
    if (this.#bytes > 4294967295) {
      this.#hBytes += this.#bytes / 4294967296 >>> 0;
      this.#bytes = this.#bytes >>> 0;
    }
    return this;
  }
  finalize() {
    if (this.#finalized) {
      return;
    }
    this.#finalized = true;
    const blocks2 = this.#blocks;
    const i = this.#lastByteIndex;
    blocks2[16] = this.#block;
    blocks2[i >> 2] |= EXTRA[i & 3];
    this.#block = blocks2[16];
    if (i >= 56) {
      if (!this.#hashed) {
        this.hash();
      }
      blocks2[0] = this.#block;
      blocks2[16] = blocks2[1] = blocks2[2] = blocks2[3] = blocks2[4] = blocks2[5] = blocks2[6] = blocks2[7] = blocks2[8] = blocks2[9] = blocks2[10] = blocks2[11] = blocks2[12] = blocks2[13] = blocks2[14] = blocks2[15] = 0;
    }
    blocks2[14] = this.#hBytes << 3 | this.#bytes >>> 29;
    blocks2[15] = this.#bytes << 3;
    this.hash();
  }
  hash() {
    let a = this.#h0;
    let b = this.#h1;
    let c = this.#h2;
    let d = this.#h3;
    let e = this.#h4;
    let f;
    let j;
    let t;
    const blocks2 = this.#blocks;
    for (j = 16; j < 80; ++j) {
      t = blocks2[j - 3] ^ blocks2[j - 8] ^ blocks2[j - 14] ^ blocks2[j - 16];
      blocks2[j] = t << 1 | t >>> 31;
    }
    for (j = 0; j < 20; j += 5) {
      f = b & c | ~b & d;
      t = a << 5 | a >>> 27;
      e = t + f + e + 1518500249 + blocks2[j] >>> 0;
      b = b << 30 | b >>> 2;
      f = a & b | ~a & c;
      t = e << 5 | e >>> 27;
      d = t + f + d + 1518500249 + blocks2[j + 1] >>> 0;
      a = a << 30 | a >>> 2;
      f = e & a | ~e & b;
      t = d << 5 | d >>> 27;
      c = t + f + c + 1518500249 + blocks2[j + 2] >>> 0;
      e = e << 30 | e >>> 2;
      f = d & e | ~d & a;
      t = c << 5 | c >>> 27;
      b = t + f + b + 1518500249 + blocks2[j + 3] >>> 0;
      d = d << 30 | d >>> 2;
      f = c & d | ~c & e;
      t = b << 5 | b >>> 27;
      a = t + f + a + 1518500249 + blocks2[j + 4] >>> 0;
      c = c << 30 | c >>> 2;
    }
    for (; j < 40; j += 5) {
      f = b ^ c ^ d;
      t = a << 5 | a >>> 27;
      e = t + f + e + 1859775393 + blocks2[j] >>> 0;
      b = b << 30 | b >>> 2;
      f = a ^ b ^ c;
      t = e << 5 | e >>> 27;
      d = t + f + d + 1859775393 + blocks2[j + 1] >>> 0;
      a = a << 30 | a >>> 2;
      f = e ^ a ^ b;
      t = d << 5 | d >>> 27;
      c = t + f + c + 1859775393 + blocks2[j + 2] >>> 0;
      e = e << 30 | e >>> 2;
      f = d ^ e ^ a;
      t = c << 5 | c >>> 27;
      b = t + f + b + 1859775393 + blocks2[j + 3] >>> 0;
      d = d << 30 | d >>> 2;
      f = c ^ d ^ e;
      t = b << 5 | b >>> 27;
      a = t + f + a + 1859775393 + blocks2[j + 4] >>> 0;
      c = c << 30 | c >>> 2;
    }
    for (; j < 60; j += 5) {
      f = b & c | b & d | c & d;
      t = a << 5 | a >>> 27;
      e = t + f + e - 1894007588 + blocks2[j] >>> 0;
      b = b << 30 | b >>> 2;
      f = a & b | a & c | b & c;
      t = e << 5 | e >>> 27;
      d = t + f + d - 1894007588 + blocks2[j + 1] >>> 0;
      a = a << 30 | a >>> 2;
      f = e & a | e & b | a & b;
      t = d << 5 | d >>> 27;
      c = t + f + c - 1894007588 + blocks2[j + 2] >>> 0;
      e = e << 30 | e >>> 2;
      f = d & e | d & a | e & a;
      t = c << 5 | c >>> 27;
      b = t + f + b - 1894007588 + blocks2[j + 3] >>> 0;
      d = d << 30 | d >>> 2;
      f = c & d | c & e | d & e;
      t = b << 5 | b >>> 27;
      a = t + f + a - 1894007588 + blocks2[j + 4] >>> 0;
      c = c << 30 | c >>> 2;
    }
    for (; j < 80; j += 5) {
      f = b ^ c ^ d;
      t = a << 5 | a >>> 27;
      e = t + f + e - 899497514 + blocks2[j] >>> 0;
      b = b << 30 | b >>> 2;
      f = a ^ b ^ c;
      t = e << 5 | e >>> 27;
      d = t + f + d - 899497514 + blocks2[j + 1] >>> 0;
      a = a << 30 | a >>> 2;
      f = e ^ a ^ b;
      t = d << 5 | d >>> 27;
      c = t + f + c - 899497514 + blocks2[j + 2] >>> 0;
      e = e << 30 | e >>> 2;
      f = d ^ e ^ a;
      t = c << 5 | c >>> 27;
      b = t + f + b - 899497514 + blocks2[j + 3] >>> 0;
      d = d << 30 | d >>> 2;
      f = c ^ d ^ e;
      t = b << 5 | b >>> 27;
      a = t + f + a - 899497514 + blocks2[j + 4] >>> 0;
      c = c << 30 | c >>> 2;
    }
    this.#h0 = this.#h0 + a >>> 0;
    this.#h1 = this.#h1 + b >>> 0;
    this.#h2 = this.#h2 + c >>> 0;
    this.#h3 = this.#h3 + d >>> 0;
    this.#h4 = this.#h4 + e >>> 0;
  }
  hex() {
    this.finalize();
    const h0 = this.#h0;
    const h1 = this.#h1;
    const h2 = this.#h2;
    const h3 = this.#h3;
    const h4 = this.#h4;
    return HEX_CHARS[h0 >> 28 & 15] + HEX_CHARS[h0 >> 24 & 15] + HEX_CHARS[h0 >> 20 & 15] + HEX_CHARS[h0 >> 16 & 15] + HEX_CHARS[h0 >> 12 & 15] + HEX_CHARS[h0 >> 8 & 15] + HEX_CHARS[h0 >> 4 & 15] + HEX_CHARS[h0 & 15] + HEX_CHARS[h1 >> 28 & 15] + HEX_CHARS[h1 >> 24 & 15] + HEX_CHARS[h1 >> 20 & 15] + HEX_CHARS[h1 >> 16 & 15] + HEX_CHARS[h1 >> 12 & 15] + HEX_CHARS[h1 >> 8 & 15] + HEX_CHARS[h1 >> 4 & 15] + HEX_CHARS[h1 & 15] + HEX_CHARS[h2 >> 28 & 15] + HEX_CHARS[h2 >> 24 & 15] + HEX_CHARS[h2 >> 20 & 15] + HEX_CHARS[h2 >> 16 & 15] + HEX_CHARS[h2 >> 12 & 15] + HEX_CHARS[h2 >> 8 & 15] + HEX_CHARS[h2 >> 4 & 15] + HEX_CHARS[h2 & 15] + HEX_CHARS[h3 >> 28 & 15] + HEX_CHARS[h3 >> 24 & 15] + HEX_CHARS[h3 >> 20 & 15] + HEX_CHARS[h3 >> 16 & 15] + HEX_CHARS[h3 >> 12 & 15] + HEX_CHARS[h3 >> 8 & 15] + HEX_CHARS[h3 >> 4 & 15] + HEX_CHARS[h3 & 15] + HEX_CHARS[h4 >> 28 & 15] + HEX_CHARS[h4 >> 24 & 15] + HEX_CHARS[h4 >> 20 & 15] + HEX_CHARS[h4 >> 16 & 15] + HEX_CHARS[h4 >> 12 & 15] + HEX_CHARS[h4 >> 8 & 15] + HEX_CHARS[h4 >> 4 & 15] + HEX_CHARS[h4 & 15];
  }
  toString() {
    return this.hex();
  }
  digest() {
    this.finalize();
    const h0 = this.#h0;
    const h1 = this.#h1;
    const h2 = this.#h2;
    const h3 = this.#h3;
    const h4 = this.#h4;
    return [
      h0 >> 24 & 255,
      h0 >> 16 & 255,
      h0 >> 8 & 255,
      h0 & 255,
      h1 >> 24 & 255,
      h1 >> 16 & 255,
      h1 >> 8 & 255,
      h1 & 255,
      h2 >> 24 & 255,
      h2 >> 16 & 255,
      h2 >> 8 & 255,
      h2 & 255,
      h3 >> 24 & 255,
      h3 >> 16 & 255,
      h3 >> 8 & 255,
      h3 & 255,
      h4 >> 24 & 255,
      h4 >> 16 & 255,
      h4 >> 8 & 255,
      h4 & 255
    ];
  }
  array() {
    return this.digest();
  }
  arrayBuffer() {
    this.finalize();
    const buffer = new ArrayBuffer(20);
    const dataView = new DataView(buffer);
    dataView.setUint32(0, this.#h0);
    dataView.setUint32(4, this.#h1);
    dataView.setUint32(8, this.#h2);
    dataView.setUint32(12, this.#h3);
    dataView.setUint32(16, this.#h4);
    return buffer;
  }
};

// https://raw.githubusercontent.com/skymethod/denoflare/f414afa279f0ab095eb40505f51afa913adc2d7e/common/local_durable_objects.ts
var LocalDurableObjects = class _LocalDurableObjects {
  static storageProviderFactories = /* @__PURE__ */ new Map([["memory", () => new InMemoryDurableObjectStorage()]]);
  moduleWorkerExportedFunctions;
  moduleWorkerEnv;
  durableObjects = /* @__PURE__ */ new Map();
  // className -> hex id -> do
  storageProvider;
  constructor(opts) {
    const { moduleWorkerExportedFunctions, moduleWorkerEnv, storageProvider } = opts;
    this.moduleWorkerExportedFunctions = moduleWorkerExportedFunctions;
    this.moduleWorkerEnv = moduleWorkerEnv || {};
    this.storageProvider = storageProvider || _LocalDurableObjects.newDurableObjectStorage;
  }
  resolveDoNamespace(doNamespace) {
    if (doNamespace.startsWith("local:")) {
      const tokens = doNamespace.split(":");
      const className = tokens[1];
      this.findConstructorForClassName(className);
      const options = {};
      for (const token of tokens.slice(2)) {
        const m = /^(.*?)=(.*?)$/.exec(token);
        if (!m) throw new Error(`Bad token '${token}' in local DO namespace: ${doNamespace}`);
        const name = m[1];
        const value = m[2];
        options[name] = value;
      }
      return new LocalDurableObjectNamespace(className, options, this.resolveDurableObject.bind(this));
    }
    return new UnimplementedDurableObjectNamespace(doNamespace);
  }
  static newDurableObjectStorage(className, id, options, dispatchAlarm) {
    const storage = options.storage || "memory";
    const rt = _LocalDurableObjects.storageProviderFactories.get(storage);
    if (rt) return rt(className, id, options, dispatchAlarm);
    throw new Error(`Bad storage: ${storage}`);
  }
  //
  findConstructorForClassName(className) {
    const ctor = this.moduleWorkerExportedFunctions[className];
    if (ctor === void 0) throw new Error(`Durable object class '${className}' not found, candidates: ${Object.keys(this.moduleWorkerExportedFunctions).join(", ")}`);
    return ctor;
  }
  resolveDurableObject(className, id, options) {
    const idStr = id.toString();
    let classObjects = this.durableObjects.get(className);
    if (classObjects !== void 0) {
      const existing = classObjects.get(idStr);
      if (existing) return existing;
    }
    const ctor = this.findConstructorForClassName(className);
    const dispatchAlarm = () => {
      console.log(`LocalDurableObjects: dispatchAlarm`);
      const obj = classObjects?.get(idStr);
      try {
        if (!obj) throw new Error(`LocalDurableObjects: object ${className} ${idStr} not found`);
        if (!obj.alarm) throw new Error(`LocalDurableObjects: object ${className} ${idStr} alarm() not implemented`);
        obj.alarm();
      } catch (e) {
        console.error(`LocalDurableObjects: error dispatching alarm`, e);
      }
    };
    const storage = this.storageProvider(className, id, options, dispatchAlarm);
    const mutex = new Mutex();
    const state = new LocalDurableObjectState(id, storage, mutex);
    const durableObject = new ctor(state, this.moduleWorkerEnv);
    if (classObjects === void 0) {
      classObjects = /* @__PURE__ */ new Map();
      this.durableObjects.set(className, classObjects);
    }
    const rt = durableObject;
    classObjects.set(idStr, rt);
    return rt;
  }
};
function computeSha1HexForStringInput(input) {
  return new Sha1().update(Bytes.ofUtf8(input).array()).hex();
}
var LocalDurableObjectNamespace = class {
  className;
  options;
  resolver;
  namesToIds = /* @__PURE__ */ new Map();
  constructor(className, options, resolver) {
    this.className = className;
    this.options = options;
    this.resolver = resolver;
  }
  newUniqueId(_opts) {
    return new LocalDurableObjectId(new Bytes(globalThis.crypto.getRandomValues(new Uint8Array(32))).hex());
  }
  idFromName(name) {
    const existing = this.namesToIds.get(name);
    if (existing) return existing;
    const sha1a = computeSha1HexForStringInput(this.className);
    const sha1b = computeSha1HexForStringInput(name);
    const rt = `${sha1a.substring(0, 24)}${sha1b}`;
    this.namesToIds.set(name, rt);
    return rt;
  }
  idFromString(hexStr) {
    return new LocalDurableObjectId(hexStr);
  }
  get(id) {
    return new LocalDurableObjectStub(this.className, id, this.options, this.resolver);
  }
};
var LocalDurableObjectStub = class {
  className;
  id;
  options;
  resolver;
  constructor(className, id, options, resolver) {
    this.className = className;
    this.id = id;
    this.options = options;
    this.resolver = resolver;
  }
  fetch(url, init) {
    if (typeof url === "string" && url.startsWith("/")) {
      url = "https://fake-host" + url;
    }
    const req = typeof url === "string" ? new Request(url, init) : init ? new Request(url, init) : url;
    return this.resolver(this.className, this.id, this.options).fetch(req);
  }
};
var LocalDurableObjectId = class {
  hexString;
  constructor(hexString) {
    this.hexString = checkMatches("hexString", hexString, /^[0-9a-f]{64}$/);
  }
  toString() {
    return this.hexString;
  }
};
var LocalDurableObjectState = class {
  id;
  storage;
  mutex;
  constructor(id, storage, mutex) {
    this.id = id;
    this.storage = storage;
    this.mutex = mutex;
  }
  waitUntil(promise) {
    promise.then(() => {
    }, (e) => consoleWarn(e));
  }
  blockConcurrencyWhile(fn) {
    return this.mutex.dispatch(fn);
  }
  acceptWebSocket(ws, tags) {
    throw new Error(`acceptWebSocket(${JSON.stringify({ ws, tags })})`);
  }
  getWebSockets(tag) {
    throw new Error(`getWebSockets(${JSON.stringify({ tag })})`);
  }
  setWebSocketAutoResponse(maybeReqResp) {
    throw new Error(`setWebSocketAutoResponse(${JSON.stringify({ maybeReqResp })})`);
  }
  getWebSocketAutoResponse() {
    throw new Error(`getWebSocketAutoResponse()`);
  }
  getWebSocketAutoResponseTimestamp(ws) {
    throw new Error(`getWebSocketAutoResponseTimestamp(${JSON.stringify({ ws })})`);
  }
  setHibernatableWebSocketEventTimeout(timeoutMs) {
    throw new Error(`setHibernatableWebSocketEventTimeout(${JSON.stringify({ timeoutMs })})`);
  }
  getHibernatableWebSocketEventTimeout() {
    throw new Error(`getHibernatableWebSocketEventTimeout()`);
  }
  getTags(ws) {
    throw new Error(`getTags(${JSON.stringify({ ws })})`);
  }
  abort(reason) {
    throw new Error(`abort(${JSON.stringify({ reason })})`);
  }
};

// https://raw.githubusercontent.com/skymethod/denoflare/f414afa279f0ab095eb40505f51afa913adc2d7e/common/fake_web_socket.ts
var FakeWebSocket = class {
  className;
  constructor(className) {
    this.className = className;
  }
  CLOSED = WebSocket.CLOSED;
  CLOSING = WebSocket.CLOSING;
  CONNECTING = WebSocket.CONNECTING;
  OPEN = WebSocket.OPEN;
  /**
   * Returns a string that indicates how binary data from the WebSocket object is exposed to scripts:
   *
   * Can be set, to change how binary data is returned. The default is "blob".
   */
  get binaryType() {
    throw new Error(`${this.className}.binaryType.get: not implemented`);
  }
  set binaryType(value) {
    throw new Error(`${this.className}.binaryType.set: not implemented`);
  }
  /**
   * Returns the number of bytes of application data (UTF-8 text and binary data) that have been queued using send() but not yet been transmitted to the network.
   *
   * If the WebSocket connection is closed, this attribute's value will only increase with each call to the send() method. (The number does not reset to zero once the connection closes.)
   */
  get bufferedAmount() {
    throw new Error(`${this.className}.bufferedAmount: not implemented`);
  }
  /**
   * Returns the extensions selected by the server, if any.
   */
  get extensions() {
    throw new Error(`${this.className}.extensions: not implemented`);
  }
  get onclose() {
    throw new Error(`${this.className}.onclose.get: not implemented`);
  }
  set onclose(value) {
    throw new Error(`${this.className}.onclose.set: not implemented`);
  }
  get onerror() {
    throw new Error(`${this.className}.onerror.get: not implemented`);
  }
  set onerror(value) {
    throw new Error(`${this.className}.onerror.set: not implemented`);
  }
  get onmessage() {
    throw new Error(`${this.className}.onmessage.get: not implemented`);
  }
  set onmessage(value) {
    throw new Error(`${this.className}.onmessage.set: not implemented`);
  }
  get onopen() {
    throw new Error(`${this.className}.onopen.get: not implemented`);
  }
  set onopen(value) {
    throw new Error(`${this.className}.onopen.set: not implemented`);
  }
  /**
   * Returns the subprotocol selected by the server, if any. It can be used in conjunction with the array form of the constructor's second argument to perform subprotocol negotiation.
   */
  get protocol() {
    throw new Error(`${this.className}.protocol: not implemented`);
  }
  /**
   * Returns the state of the WebSocket object's connection. It can have the values described below.
   */
  get readyState() {
    throw new Error(`${this.className}.readyState: not implemented`);
  }
  /**
   * Returns the URL that was used to establish the WebSocket connection.
   */
  get url() {
    throw new Error(`${this.className}.url: not implemented`);
  }
  /**
   * Closes the WebSocket connection, optionally using code as the the WebSocket connection close code and reason as the the WebSocket connection close reason.
   */
  close(code, reason) {
    throw new Error(`${this.className}.close: not implemented`);
  }
  /**
   * Transmits data using the WebSocket connection. data can be a string, a Blob, an ArrayBuffer, or an ArrayBufferView.
   */
  send(data) {
    throw new Error(`${this.className}.send: not implemented`);
  }
  addEventListener(type, listener, options) {
    throw new Error(`${this.className}.addEventListener: not implemented`);
  }
  /** Removes the event listener in target's event listener list with the same
  * type, callback, and options. */
  removeEventListener(type, callback, options) {
    throw new Error(`${this.className}.removeEventListener: not implemented`);
  }
  /** Dispatches a synthetic event event to target and returns true if either
   * event's cancelable attribute value is false or its preventDefault() method
   * was not invoked, and false otherwise. */
  dispatchEvent(event) {
    throw new Error(`${this.className}.dispatchEvent: not implemented`);
  }
};

// https://raw.githubusercontent.com/skymethod/denoflare/f414afa279f0ab095eb40505f51afa913adc2d7e/common/local_web_sockets.ts
var LocalWebSockets = class {
  static VERBOSE = false;
  pairs = /* @__PURE__ */ new Map();
  nextId = 1;
  allocateNewWebSocketPair() {
    const id = this.nextId++;
    const client = new LocalWebSocket(id, "client", this);
    const server = new LocalWebSocket(id, "server", this);
    this.pairs.set(id, { client, server });
    return { server, client };
  }
  dispatch(id, to, data) {
    const pair = this.pairs.get(id);
    if (!pair) throw new Error(`Bad id: ${id}`);
    (to === "client" ? pair.client : pair.server).dispatchMessageData(data);
  }
};
var LocalWebSocket = class extends FakeWebSocket {
  _className;
  sockets;
  side;
  id;
  pendingMessageEvents = [];
  messageListeners = [];
  closeListeners = [];
  errorListeners = [];
  _accepted = false;
  _onmessage = null;
  _onopen = null;
  _onclose = null;
  _onerror = null;
  _readyState = WebSocket.CONNECTING;
  constructor(id, side, sockets) {
    const className = `LocalWebSocket(${side})`;
    super(className);
    this._className = className;
    this.id = id;
    this.side = side;
    this.sockets = sockets;
  }
  //
  get onmessage() {
    return this._onmessage;
  }
  set onmessage(value) {
    this._onmessage = value;
  }
  get onopen() {
    return this._onopen;
  }
  set onopen(value) {
    this._onopen = value;
  }
  get onclose() {
    return this._onclose;
  }
  set onclose(value) {
    this._onclose = value;
  }
  get onerror() {
    return this._onerror;
  }
  set onerror(value) {
    this._onerror = value;
  }
  get readyState() {
    return this._readyState;
  }
  accept() {
    if (this._accepted) throw new Error(`${this._className}: Cannot accept(), already accepted`);
    if (LocalWebSockets.VERBOSE) console.log(`${this._className}: accept!`);
    this._readyState = WebSocket.OPEN;
    this._accepted = true;
    for (const event of this.pendingMessageEvents) {
      this.dispatchEvent(event);
    }
    this.pendingMessageEvents.splice(0);
  }
  addEventListener(type, listener, options) {
    if (listener === null) return;
    if (options) throw new Error(`${this._className}: addEventListener.${type}.options not implemented`);
    if (type === "message") {
      this.messageListeners.push(listener);
    } else if (type === "close") {
      this.closeListeners.push(listener);
    } else if (type === "error") {
      this.errorListeners.push(listener);
    } else {
      throw new Error(`${this._className}.addEventListener: '${type}' not implemented`);
    }
  }
  send(data) {
    if (LocalWebSockets.VERBOSE) console.log(`${this._className}.${this.id}: send ${data}`);
    if (!this._accepted) throw new Error(`${this._className}: Cannot send() before accept()`);
    this.sockets.dispatch(this.id, this.side === "client" ? "server" : "client", data);
  }
  //
  dispatchMessageData(data) {
    if (LocalWebSockets.VERBOSE) console.log(`${this._className}.${this.id}: dispatchMessageData ${data} accepted=${this._accepted} this.onmessage=${!!this.onmessage}`);
    const event = new MessageEvent("message", { data });
    if (this._accepted) {
      this.dispatchMessageEvent(event);
    } else {
      this.pendingMessageEvents.push(event);
    }
  }
  //
  dispatchMessageEvent(event) {
    if (this.onmessage) {
      this.onmessage(event);
    }
    for (const listener of this.messageListeners) {
      if (typeof listener === "object") {
        listener.handleEvent(event);
      } else {
        listener(event);
      }
    }
  }
  dispatchCloseEvent(event) {
    if (this.onclose) {
      this.onclose(event);
    }
    for (const listener of this.closeListeners) {
      if (typeof listener === "object") {
        listener.handleEvent(event);
      } else {
        listener(event);
      }
    }
  }
};

// https://raw.githubusercontent.com/skymethod/denoflare/f414afa279f0ab095eb40505f51afa913adc2d7e/common/rpc_stub_web_sockets.ts
var RpcStubWebSockets = class {
  channel;
  isolateId;
  pairs = /* @__PURE__ */ new Map();
  nextId = 1;
  constructor(channel) {
    this.channel = channel;
    this.isolateId = crypto.randomUUID().split("-").pop();
    channel.addRequestHandler("ws-to-stub", (data) => {
      const { method } = data;
      if (method === "send") {
        const { data: messageData, isolateId, id, to } = data;
        if (typeof isolateId !== "string" || isolateId !== this.isolateId) throw new Error(`Bad isolateId: ${isolateId}`);
        if (typeof id !== "number") throw new Error(`Bad id: ${id}`);
        if (to !== "client" && to !== "server") throw new Error(`Bad to: ${to}`);
        const pair = this.pairs.get(id);
        if (!pair) throw new Error(`Bad id: ${id}`);
        pair.get(to).dispatchMessageData(messageData);
      } else if (method === "close") {
        const { code, reason, isolateId, id, to } = data;
        if (typeof isolateId !== "string" || isolateId !== this.isolateId) throw new Error(`Bad isolateId: ${isolateId}`);
        if (typeof id !== "number") throw new Error(`Bad id: ${id}`);
        if (to !== "client" && to !== "server") throw new Error(`Bad to: ${to}`);
        const pair = this.pairs.get(id);
        if (!pair) throw new Error(`Bad id: ${id}`);
        if (code !== void 0 && typeof code !== "number") throw new Error(`Bad code: ${code}`);
        if (reason !== void 0 && typeof reason !== "string") throw new Error(`Bad reason: ${reason}`);
        pair.get(to).dispatchClose(code, reason);
      } else {
        throw new Error(`RpcStubWebSockets: ws-to-stub method '${method}' not implemented`);
      }
      return Promise.resolve();
    });
  }
  allocateNewWebSocketPair() {
    const id = this.nextId++;
    const { isolateId, channel } = this;
    const pair = new Pair(channel, isolateId, id);
    this.pairs.set(id, pair);
    channel.fireRequest("ws-allocate", { isolateId, id });
    return pair;
  }
  packWebSocket(socket) {
    if (!isRpcStubWebSocket(socket)) throw new Error(`RpcStubWebSockets: packWebSocket: must be RpcStubWebSocket`);
    return `${socket.isolateId}-${socket.id}-${socket.side}`;
  }
  unpackWebSocket(_socket) {
    throw new Error(`RpcStubWebSockets: unpackWebSocket not implemented`);
  }
};
function isRpcStubWebSocket(socket) {
  return socket.kind === "RpcStubWebSocket";
}
function dumpOpenWarning() {
  console.warn("WARNING: ws open event is not called for cf sockets, opened after .accept()");
}
var Pair = class {
  server;
  client;
  constructor(channel, isolateId, id) {
    this.server = new RpcStubWebSocket("server", channel, isolateId, id);
    this.client = new RpcStubWebSocket("client", channel, isolateId, id);
  }
  get(side) {
    return side === "client" ? this.client : this.server;
  }
};
var RpcStubWebSocket = class extends FakeWebSocket {
  kind = "RpcStubWebSocket";
  isolateId;
  id;
  side;
  _className;
  channel;
  messageListeners = [];
  closeListeners = [];
  errorListeners = [];
  openListeners = [];
  nextSeq = 1;
  _onmessage = null;
  _onclose = null;
  _onopen = null;
  _onerror = null;
  constructor(side, channel, isolateId, id) {
    const className = `RpcStubWebSocket(${side},${isolateId},${id})`;
    super(className);
    this._className = className;
    this.channel = channel;
    this.isolateId = isolateId;
    this.id = id;
    this.side = side;
  }
  get onmessage() {
    return this._onmessage;
  }
  set onmessage(value) {
    this._onmessage = value;
  }
  get onclose() {
    return this._onclose;
  }
  set onclose(value) {
    this._onclose = value;
  }
  get onopen() {
    return this._onopen;
  }
  set onopen(value) {
    this._onopen = value;
    dumpOpenWarning();
  }
  // not implemented yet, but don't crash
  get onerror() {
    return this._onerror;
  }
  set onerror(value) {
    this._onerror = value;
  }
  get binaryType() {
    return "arraybuffer";
  }
  accept() {
    const { isolateId, id, side } = this;
    const seq = this.nextSeq++;
    this.channel.fireRequest("ws-from-stub", { method: "accept", id, isolateId, seq, side });
  }
  addEventListener(type, listener, options) {
    if (listener === null) return;
    if (options) throw new Error(`${this._className}.addEventListener: options not implemented`);
    if (type === "message") {
      this.messageListeners.push(listener);
    } else if (type === "close") {
      this.closeListeners.push(listener);
    } else if (type === "error") {
      this.errorListeners.push(listener);
    } else if (type === "open") {
      this.openListeners.push(listener);
      dumpOpenWarning();
    } else {
      throw new Error(`${this._className}.addEventListener: '${type}' not implemented`);
    }
  }
  send(data) {
    const { isolateId, id, side } = this;
    const seq = this.nextSeq++;
    this.channel.fireRequest("ws-from-stub", { method: "send", id, isolateId, data, seq, side });
  }
  //
  dispatchMessageData(data) {
    const event = new MessageEvent("message", { data });
    if (this.onmessage) {
      this.onmessage(event);
    }
    for (const listener of this.messageListeners) {
      if (typeof listener === "object") {
        listener.handleEvent(event);
      } else {
        listener(event);
      }
    }
  }
  dispatchClose(code, reason) {
    const event = new CloseEvent("close", { code, reason });
    if (this.onclose) {
      this.onclose(event);
    }
    for (const listener of this.closeListeners) {
      if (typeof listener === "object") {
        listener.handleEvent(event);
      } else {
        listener(event);
      }
    }
  }
};

// https://raw.githubusercontent.com/skymethod/denoflare/f414afa279f0ab095eb40505f51afa913adc2d7e/common/storage/in_memory_alarms.ts
var InMemoryAlarms = class {
  dispatchAlarm;
  // alarms not durable, kept in memory only
  alarm = null;
  alarmTimeoutId = 0;
  constructor(dispatchAlarm) {
    this.dispatchAlarm = dispatchAlarm;
  }
  getAlarm(options = {}) {
    const { allowConcurrency } = options;
    if (allowConcurrency !== void 0) throw new Error(`InMemoryAlarms.getAlarm(allowConcurrency) not implemented: options=${JSON.stringify(options)}`);
    return Promise.resolve(this.alarm);
  }
  setAlarm(scheduledTime, options = {}) {
    const { allowUnconfirmed } = options;
    if (allowUnconfirmed !== void 0) throw new Error(`InMemoryAlarms.setAlarm(allowUnconfirmed) not implemented: options=${JSON.stringify(options)}`);
    this.alarm = Math.max(Date.now(), typeof scheduledTime === "number" ? scheduledTime : scheduledTime.getTime());
    this.rescheduleAlarm();
    return Promise.resolve();
  }
  deleteAlarm(options = {}) {
    const { allowUnconfirmed } = options;
    if (allowUnconfirmed !== void 0) throw new Error(`InMemoryAlarms.deleteAlarm(allowUnconfirmed) not implemented: options=${JSON.stringify(options)}`);
    this.alarm = null;
    this.rescheduleAlarm();
    return Promise.resolve();
  }
  //
  rescheduleAlarm() {
    clearTimeout(this.alarmTimeoutId);
    if (typeof this.alarm === "number") {
      this.alarmTimeoutId = setTimeout(() => {
        this.alarm = null;
        this.dispatchAlarm();
      }, Math.max(0, this.alarm - Date.now()));
    }
  }
};

// https://raw.githubusercontent.com/skymethod/denoflare/f414afa279f0ab095eb40505f51afa913adc2d7e/common/rpc_stub_durable_object_storage.ts
function makeRpcStubDurableObjectStorageProvider(channel) {
  return (className, id, options, dispatchAlarm) => {
    if ((options.storage || "memory") === "memory") return new InMemoryDurableObjectStorage();
    return new RpcStubDurableObjectStorage(channel, { className, id, options }, dispatchAlarm);
  };
}
var RpcStubDurableObjectStorage = class {
  channel;
  reference;
  alarms;
  constructor(channel, reference, dispatchAlarm) {
    this.channel = channel;
    this.reference = reference;
    this.alarms = new InMemoryAlarms(dispatchAlarm);
  }
  async transaction(closure) {
    const txn = new RpcStubDurableObjectStorageTransaction(this);
    return await Promise.resolve(closure(txn));
  }
  async sync() {
    const { reference } = this;
    const sync = { method: "sync", reference };
    return await this.channel.sendRequest("do-storage", sync, (data) => {
      const { error } = data;
      if (typeof error === "string") throw new Error(error);
    });
  }
  async deleteAll() {
    const { reference } = this;
    const deleteAll = { method: "delete-all", reference };
    return await this.channel.sendRequest("do-storage", deleteAll, (data) => {
      const { error } = data;
      if (typeof error === "string") throw new Error(error);
    });
  }
  get(keyOrKeys, opts) {
    return this._get(keyOrKeys, opts);
  }
  async _get(keyOrKeys, opts = {}) {
    const { reference } = this;
    if (typeof keyOrKeys === "string") {
      const key = keyOrKeys;
      const get1 = { method: "get1", reference, key, opts };
      return await this.channel.sendRequest("do-storage", get1, (data) => {
        const { error, value } = data;
        if (typeof error === "string") throw new Error(error);
        return value;
      });
    } else if (isStringArray(keyOrKeys)) {
      const keys = keyOrKeys;
      const get2 = { method: "get2", reference, keys, opts };
      return await this.channel.sendRequest("do-storage", get2, (data) => {
        const { error, value } = data;
        if (typeof error === "string") throw new Error(error);
        return value;
      });
    }
    throw new Error(`RpcStubDurableObjectStorage.get not implemented ${keyOrKeys} ${opts}`);
  }
  put(arg1, arg2, arg3) {
    return this._put(arg1, arg2, arg3);
  }
  async _put(arg1, arg2, arg3) {
    const { reference } = this;
    if (typeof arg1 === "string") {
      const key = arg1;
      const value = arg2;
      const opts = arg3;
      const put1 = { method: "put1", reference, key, value, opts };
      return await this.channel.sendRequest("do-storage", put1, (data) => {
        const { error } = data;
        if (typeof error === "string") throw new Error(error);
      });
    } else if (typeof arg1 === "object" && !Array.isArray(arg1)) {
      const entries = arg1;
      const opts = arg3;
      const put2 = { method: "put2", reference, entries, opts };
      return await this.channel.sendRequest("do-storage", put2, (data) => {
        const { error } = data;
        if (typeof error === "string") throw new Error(error);
      });
    }
    throw new Error(`RpcStubDurableObjectStorage.put not implemented ${arg1} ${arg2} ${arg3}`);
  }
  delete(keyOrKeys, opts) {
    return this._delete(keyOrKeys, opts);
  }
  async _delete(keyOrKeys, opts) {
    const { reference } = this;
    if (typeof keyOrKeys === "string") {
      const key = keyOrKeys;
      const delete1 = { method: "delete1", reference, key, opts };
      return await this.channel.sendRequest("do-storage", delete1, (data) => {
        const { error, value } = data;
        if (typeof error === "string") throw new Error(error);
        return value;
      });
    } else if (isStringArray(keyOrKeys)) {
      const keys = keyOrKeys;
      const delete2 = { method: "delete2", reference, keys, opts };
      return await this.channel.sendRequest("do-storage", delete2, (data) => {
        const { error, value } = data;
        if (typeof error === "string") throw new Error(error);
        return value;
      });
    }
    throw new Error(`RpcStubDurableObjectStorage.delete not implemented ${keyOrKeys} ${opts}`);
  }
  async list(options = {}) {
    const { reference } = this;
    const list = { method: "list", reference, options };
    return await this.channel.sendRequest("do-storage", list, (data) => {
      const { error, value } = data;
      if (typeof error === "string") throw new Error(error);
      return value;
    });
  }
  getAlarm(options) {
    return this.alarms.getAlarm(options);
  }
  setAlarm(scheduledTime, options) {
    return this.alarms.setAlarm(scheduledTime, options);
  }
  deleteAlarm(options) {
    return this.alarms.deleteAlarm(options);
  }
  getBookmarkForTime(timestamp) {
    throw new Error(`RpcStubDurableObjectStorage.getBookmarkForTime(${JSON.stringify({ timestamp })}) not implemented`);
  }
  getCurrentBookmark() {
    throw new Error(`RpcStubDurableObjectStorage.getCurrentBookmark() not implemented`);
  }
  onNextSessionRestoreBookmark(bookmark) {
    throw new Error(`RpcStubDurableObjectStorage.onNextSessionRestoreBookmark(${JSON.stringify({ bookmark })}) not implemented`);
  }
  transactionSync(_closure) {
    throw new Error(`RpcStubDurableObjectStorage.transactionSync() not implemented`);
  }
  get sql() {
    throw new Error(`RpcStubDurableObjectStorage.sql not implemented`);
  }
};
var RpcStubDurableObjectStorageTransaction = class {
  storage;
  constructor(storage) {
    this.storage = storage;
  }
  rollback() {
    throw new Error(`RpcStubDurableObjectStorageTransaction.rollback not implemented`);
  }
  deleteAll() {
    return this.storage.deleteAll();
  }
  get(keyOrKeys, opts) {
    return this.storage._get(keyOrKeys, opts);
  }
  put(arg1, arg2, arg3) {
    return this.storage._put(arg1, arg2, arg3);
  }
  delete(keyOrKeys, opts) {
    return this.storage._delete(keyOrKeys, opts);
  }
  list(options = {}) {
    return this.storage.list(options);
  }
  getAlarm(options) {
    return this.storage.getAlarm(options);
  }
  setAlarm(scheduledTime, options) {
    return this.storage.setAlarm(scheduledTime, options);
  }
  deleteAlarm(options) {
    return this.storage.deleteAlarm(options);
  }
};

// https://raw.githubusercontent.com/skymethod/denoflare/f414afa279f0ab095eb40505f51afa913adc2d7e/common/rpc_r2_model.ts
function unpackR2Objects(packed) {
  return {
    objects: packed.objects.map(unpackR2Object),
    truncated: packed.truncated,
    cursor: packed.cursor,
    delimitedPrefixes: packed.delimitedPrefixes
  };
}
function unpackR2Object(packed) {
  return {
    key: packed.key,
    version: packed.version,
    size: packed.size,
    etag: packed.etag,
    httpEtag: packed.httpEtag,
    checksums: unpackR2Checksums(packed.checksums),
    uploaded: new Date(packed.uploaded),
    httpMetadata: unpackR2HTTPMetadata(packed.httpMetadata),
    customMetadata: packed.customMetadata,
    writeHttpMetadata: (_headers) => {
      throw new Error(`writeHttpMetadata not supported`);
    }
  };
}
function packR2HTTPMetadata(unpacked) {
  return {
    contentType: unpacked.contentType,
    contentLanguage: unpacked.contentLanguage,
    contentDisposition: unpacked.contentDisposition,
    contentEncoding: unpacked.contentEncoding,
    cacheControl: unpacked.cacheControl,
    cacheExpiry: unpacked.cacheExpiry?.toISOString()
  };
}
function unpackR2HTTPMetadata(packed) {
  return {
    contentType: packed.contentType,
    contentLanguage: packed.contentLanguage,
    contentDisposition: packed.contentDisposition,
    contentEncoding: packed.contentEncoding,
    cacheControl: packed.cacheControl,
    cacheExpiry: unpackOptionalDate(packed.cacheExpiry)
  };
}
function unpackR2Checksums(packed) {
  return {
    md5: unpackArrayBuffer(packed.md5),
    sha1: unpackArrayBuffer(packed.sha1),
    sha256: unpackArrayBuffer(packed.sha256),
    sha384: unpackArrayBuffer(packed.sha384),
    sha512: unpackArrayBuffer(packed.sha512)
  };
}
function packR2GetOptions(unpacked) {
  const { onlyIf, range } = unpacked;
  return {
    onlyIf: onlyIf === void 0 ? void 0 : onlyIf instanceof Headers ? packHeaders(onlyIf) : packR2Conditional(onlyIf),
    range
  };
}
function packR2Conditional(unpacked) {
  return {
    etagMatches: unpacked.etagMatches,
    etagDoesNotMatch: unpacked.etagDoesNotMatch,
    uploadedBefore: unpacked.uploadedBefore?.toISOString(),
    uploadedAfter: unpacked.uploadedAfter?.toISOString()
  };
}
function packHeaders(headers) {
  return [...headers];
}
function packR2PutOptions(unpacked) {
  return {
    onlyIf: unpacked.onlyIf === void 0 ? void 0 : unpacked.onlyIf instanceof Headers ? packHeaders(unpacked.onlyIf) : packR2Conditional(unpacked.onlyIf),
    httpMetadata: unpacked.httpMetadata === void 0 ? void 0 : unpacked.httpMetadata instanceof Headers ? packHeaders(unpacked.httpMetadata) : packR2HTTPMetadata(unpacked.httpMetadata),
    customMetadata: unpacked.customMetadata,
    md5: packHash(unpacked.md5),
    sha1: packHash(unpacked.sha1),
    sha256: packHash(unpacked.sha256),
    sha384: packHash(unpacked.sha384),
    sha512: packHash(unpacked.sha512)
  };
}
function packR2MultipartOptions(unpacked) {
  return {
    httpMetadata: unpacked.httpMetadata === void 0 ? void 0 : unpacked.httpMetadata instanceof Headers ? packHeaders(unpacked.httpMetadata) : packR2HTTPMetadata(unpacked.httpMetadata),
    customMetadata: unpacked.customMetadata
  };
}
function unpackOptionalDate(packed) {
  return typeof packed === "string" ? new Date(packed) : void 0;
}
function packHash(hash) {
  if (hash === void 0 || typeof hash === "string") return hash;
  return new Bytes(new Uint8Array(hash)).hex();
}
function unpackArrayBuffer(hex) {
  if (hex === void 0) return void 0;
  return Bytes.ofHex(hex).array().buffer;
}

// https://raw.githubusercontent.com/skymethod/denoflare/f414afa279f0ab095eb40505f51afa913adc2d7e/common/rpc_r2_bucket.ts
var RpcR2Bucket = class {
  bucketName;
  channel;
  bodyResolver;
  bodies;
  constructor(bucketName, channel, bodyResolver, bodies) {
    this.bucketName = bucketName;
    this.channel = channel;
    this.bodyResolver = bodyResolver;
    this.bodies = bodies;
  }
  async list(options) {
    const { bucketName } = this;
    const req = { bucketName, options };
    return await this.channel.sendRequest("r2-bucket-list", req, (responseData) => {
      const { objects: packedObjects } = responseData;
      return unpackR2Objects(packedObjects);
    });
  }
  async head(key) {
    const { bucketName } = this;
    const req = { bucketName, key };
    return await this.channel.sendRequest("r2-bucket-head", req, (responseData) => {
      const { object: packedObject } = responseData;
      return packedObject === void 0 ? null : unpackR2Object(packedObject);
    });
  }
  async get(key, options) {
    const { bucketName } = this;
    const req = { bucketName, key, options: options === void 0 ? void 0 : packR2GetOptions(options) };
    return await this.channel.sendRequest("r2-bucket-get", req, (responseData) => {
      const { result } = responseData;
      if (result === void 0) return null;
      const { object, bodyId } = result;
      if (typeof bodyId === "number") {
        const stream = this.bodyResolver(bodyId);
        return new RpcR2ObjectBody(unpackR2Object(object), stream);
      } else {
        return unpackR2Object(object);
      }
    });
  }
  async put(key, value, options) {
    const { bucketName, bodies } = this;
    const { bodyId, bodyText, bodyBytes, bodyNull } = await packPutValue(value, bodies);
    const req = { bucketName, key, options: options === void 0 ? void 0 : packR2PutOptions(options), bodyId, bodyText, bodyBytes, bodyNull };
    return await this.channel.sendRequest("r2-bucket-put", req, (responseData) => {
      const { object: packedObject } = responseData;
      return unpackR2Object(packedObject);
    });
  }
  async delete(keys) {
    const { bucketName } = this;
    const req = { bucketName, keys };
    await this.channel.sendRequest("r2-bucket-delete", req, () => {
    });
  }
  async createMultipartUpload(key, options) {
    const { bucketName, bodies, channel } = this;
    const req = { bucketName, key, options: options === void 0 ? void 0 : packR2MultipartOptions(options) };
    return await this.channel.sendRequest("r2-bucket-create-multipart-upload", req, (responseData) => {
      const { key: key2, uploadId } = responseData;
      return new RpcR2MultipartUpload(bucketName, bodies, channel, key2, uploadId);
    });
  }
  async resumeMultipartUpload(key, uploadId) {
    const { bucketName, bodies, channel } = this;
    const req = { bucketName, key, uploadId };
    return await this.channel.sendRequest("r2-bucket-resume-multipart-upload", req, (responseData) => {
      const { key: key2, uploadId: uploadId2 } = responseData;
      return new RpcR2MultipartUpload(bucketName, bodies, channel, key2, uploadId2);
    });
  }
};
async function packPutValue(value, bodies) {
  let bodyId;
  let bodyText;
  let bodyBytes;
  let bodyNull = false;
  if (value === null) {
    bodyNull = true;
  } else if (typeof value === "string") {
    bodyText = value;
  } else if (value instanceof ArrayBuffer) {
    bodyBytes = new Uint8Array(value);
  } else if (value instanceof Blob) {
    bodyBytes = new Uint8Array(await value.arrayBuffer());
  } else if (value instanceof ReadableStream) {
    bodyId = bodies.computeBodyId(value);
  } else {
    bodyBytes = new Uint8Array(value.buffer);
  }
  return { bodyId, bodyText, bodyBytes, bodyNull };
}
var RpcR2ObjectBody = class {
  key;
  version;
  size;
  etag;
  httpEtag;
  checksums;
  uploaded;
  httpMetadata;
  customMetadata;
  body;
  get bodyUsed() {
    throw new Error(`bodyUsed not supported`);
  }
  constructor(object, stream) {
    this.key = object.key;
    this.version = object.version;
    this.size = object.size;
    this.etag = object.etag;
    this.httpEtag = object.httpEtag;
    this.checksums = object.checksums;
    this.uploaded = object.uploaded;
    this.httpMetadata = object.httpMetadata;
    this.customMetadata = object.customMetadata;
    this.body = stream;
  }
  async arrayBuffer() {
    return (await Bytes.ofStream(this.body)).array().buffer;
  }
  async text() {
    return (await Bytes.ofStream(this.body)).utf8();
  }
  async json() {
    return JSON.parse(await this.text());
  }
  async blob() {
    return new Blob([await this.arrayBuffer()]);
  }
  writeHttpMetadata(headers) {
    const { contentType, contentLanguage, contentDisposition, contentEncoding, cacheControl, cacheExpiry } = this.httpMetadata;
    if (contentType !== void 0) headers.set("content-type", contentType);
    if (contentLanguage !== void 0) headers.set("content-language", contentLanguage);
    if (contentDisposition !== void 0) headers.set("content-disposition", contentDisposition);
    if (contentEncoding !== void 0) headers.set("content-encoding", contentEncoding);
    if (cacheControl !== void 0) headers.set("cache-control", cacheControl);
    if (cacheExpiry !== void 0) headers.set("expires", cacheExpiry.toString());
  }
};
var RpcR2MultipartUpload = class {
  bucketName;
  bodies;
  channel;
  key;
  uploadId;
  constructor(bucketName, bodies, channel, key, uploadId) {
    this.bucketName = bucketName;
    this.bodies = bodies;
    this.channel = channel;
    this.key = key;
    this.uploadId = uploadId;
  }
  async uploadPart(partNumber, value) {
    const { bucketName, bodies, channel, key, uploadId } = this;
    const { bodyId, bodyText, bodyBytes, bodyNull } = await packPutValue(value, bodies);
    const req = { bucketName, key, uploadId, partNumber, bodyId, bodyText, bodyBytes, bodyNull };
    return await channel.sendRequest("r2-mpu-upload-part", req, (responseData) => {
      const { partNumber: partNumber2, etag } = responseData;
      return { partNumber: partNumber2, etag };
    });
  }
  async abort() {
    const { bucketName, channel, key, uploadId } = this;
    const req = { bucketName, key, uploadId };
    await channel.sendRequest("r2-mpu-abort", req, () => {
    });
  }
  async complete(uploadedParts) {
    const { bucketName, channel, key, uploadId } = this;
    const req = { bucketName, key, uploadId, uploadedParts };
    return await channel.sendRequest("r2-mpu-complete", req, (responseData) => {
      const { object: packedObject } = responseData;
      return unpackR2Object(packedObject);
    });
  }
};

// https://raw.githubusercontent.com/skymethod/denoflare/f414afa279f0ab095eb40505f51afa913adc2d7e/common/noop_analytics_engine.ts
var NoopAnalyticsEngine = class _NoopAnalyticsEngine {
  dataset;
  constructor(dataset) {
    this.dataset = dataset;
  }
  writeDataPoint(event) {
    console.log(`${this.dataset}.writeDataPoint (no-op)`, event);
  }
  static provider = (dataset) => new _NoopAnalyticsEngine(dataset);
};

// https://raw.githubusercontent.com/skymethod/denoflare/f414afa279f0ab095eb40505f51afa913adc2d7e/common/crypto_keys.ts
function parseCryptoKeyDef(json) {
  const obj = JSON.parse(json);
  const { format, algorithm, usages, base64 } = obj;
  if (typeof format !== "string") throw new Error(`Bad format: ${JSON.stringify(format)} in ${JSON.stringify(obj)}`);
  if (!isStringRecord(algorithm)) throw new Error(`Bad algorithm: ${JSON.stringify(algorithm)} in ${JSON.stringify(obj)}`);
  const { name } = algorithm;
  if (typeof name !== "string") throw new Error(`Bad algorithm.name: ${JSON.stringify(name)} in ${JSON.stringify(obj)}`);
  if (!Array.isArray(usages) || !usages.every(isKeyUsage)) throw new Error(`Bad usages: ${JSON.stringify(usages)} in ${JSON.stringify(obj)}`);
  if (typeof base64 !== "string") throw new Error(`Bad base64: ${JSON.stringify(base64)} in ${JSON.stringify(obj)}`);
  return { format, algorithm, usages, base64 };
}
async function toCryptoKey(def) {
  const { format, base64, algorithm, usages } = def;
  if (format !== "pkcs8" && format !== "raw" && format !== "spki") throw new Error(`Format ${format} not supported`);
  const keyData = Bytes.ofBase64(base64).array();
  return await crypto.subtle.importKey(format, keyData, algorithm, true, usages);
}
async function cryptoKeyProvider(json) {
  const def = parseCryptoKeyDef(json);
  return await toCryptoKey(def);
}
function isKeyUsage(obj) {
  return typeof obj === "string" && /^decrypt|deriveBits|deriveKey|encrypt|sign|unwrapKey|verify|wrapKey$/.test(obj);
}

// https://raw.githubusercontent.com/skymethod/denoflare/f414afa279f0ab095eb40505f51afa913adc2d7e/common/signal.ts
var Signal = class {
  promise;
  resolveFn;
  rejectFn;
  constructor() {
    this.promise = new Promise((resolve, reject) => {
      this.resolveFn = resolve;
      this.rejectFn = reject;
    });
  }
  resolve(result) {
    this.resolveFn(result);
  }
  reject(reason) {
    this.rejectFn(reason);
  }
};

// https://raw.githubusercontent.com/skymethod/denoflare/f414afa279f0ab095eb40505f51afa913adc2d7e/common/cloudflare_sockets.ts
function parseSocketAddress(address) {
  if (typeof address === "string") {
    const m = /^([a-z0-9.-]+):(\d+)$/.exec(address);
    if (!m) throw new Error(`Bad address: ${address}`);
    const [_, hostname, portStr] = m;
    const port = parseInt(portStr);
    return { hostname, port };
  }
  return address;
}

// https://raw.githubusercontent.com/skymethod/denoflare/f414afa279f0ab095eb40505f51afa913adc2d7e/common/rpc_cloudflare_sockets.ts
function makeRpcCloudflareSockets(channel) {
  return {
    connect: (address, options) => new RpcCloudflareSocket(parseSocketAddress(address), options ?? {}, channel)
  };
}
var RpcCloudflareSocket = class {
  readable;
  writable;
  closed;
  address;
  id = crypto.randomUUID().toLowerCase();
  closedSignal = new Signal();
  channel;
  startTlsAllowed;
  _writable;
  _readable;
  startedTls = false;
  _closed = false;
  constructor(address, options, channel) {
    this.address = address;
    this.channel = channel;
    const { allowHalfOpen, secureTransport } = options;
    if (allowHalfOpen) throw new Error(`unimplemented: allowHalfOpen`);
    this.closed = this.closedSignal.promise;
    const stream1 = new TransformStream();
    this.readable = stream1.readable;
    this._writable = stream1.writable;
    const stream2 = new TransformStream();
    this.writable = stream2.writable;
    this._readable = stream2.readable;
    this.startTlsAllowed = secureTransport === "starttls";
    if (this.startTlsAllowed) return;
    const tls = secureTransport === "on";
    this.open({ tls });
  }
  async close() {
    if (this._closed || this.startTlsAllowed && !this.startedTls) throw new Error(`Not closeable`);
    this._closed = true;
    const { id } = this;
    const msg = { id };
    await this.channel.sendRequest("socket-close", msg, () => {
    });
    this.closedSignal.resolve(void 0);
  }
  startTls() {
    if (!this.startTlsAllowed) throw new Error(`startTls() requires secureTransport = 'starttls' when calling connect()`);
    if (this.startedTls) throw new Error(`Already called startTls()`);
    this.startedTls = true;
    this.open({ tls: true });
    return this;
  }
  //
  open({ tls }) {
    const { id, address, channel } = this;
    const { hostname, port } = address;
    const writer = this._writable.getWriter();
    channel.addRequestHandler("socket-data", async ({ id: id2, bytes, done }) => {
      if (id2 !== this.id) return;
      if (bytes) await writer.write(bytes);
      if (done) await writer.close();
    });
    (async () => {
      const msg = { id, hostname, port, tls };
      await this.channel.sendRequest("socket-open", msg, () => {
      });
      for await (const bytes of this._readable) {
        const msg2 = { id, bytes, done: false };
        await this.channel.sendRequest("socket-data", msg2, () => {
        });
      }
      {
        const msg2 = { id, bytes: void 0, done: true };
        await this.channel.sendRequest("socket-data", msg2, () => {
        });
      }
    })();
  }
};

// https://raw.githubusercontent.com/skymethod/denoflare/f414afa279f0ab095eb40505f51afa913adc2d7e/common/rpc_stub_d1_database.ts
function makeRpcStubD1DatabaseProvider(channel) {
  return (d1DatabaseUuid) => {
    return new RpcD1Database(channel, { d1DatabaseUuid });
  };
}
var RpcD1Database = class {
  channel;
  d1DatabaseUuid;
  constructor(channel, { d1DatabaseUuid }) {
    this.channel = channel;
    this.d1DatabaseUuid = d1DatabaseUuid;
  }
  prepare(query) {
    const { channel, d1DatabaseUuid } = this;
    return new RpcD1PreparedStatement(channel, { d1DatabaseUuid, query, params: [] });
  }
  dump() {
    throw new Error(`dump() not implemented`);
  }
  async batch(statements) {
    const { d1DatabaseUuid } = this;
    const request = { method: "batch", d1DatabaseUuid, statements: statements.map(RpcD1PreparedStatement.toPacked) };
    return await this.channel.sendRequest("d1", request, (data) => {
      if ("error" in data) throw new Error(data.error);
      return data.result;
    });
  }
  async exec(query) {
    const { d1DatabaseUuid } = this;
    const request = { method: "exec", d1DatabaseUuid, query };
    return await this.channel.sendRequest("d1", request, (data) => {
      if ("error" in data) throw new Error(data.error);
      return data.result;
    });
  }
};
function checkParamValue(value, index) {
  if (value === null || typeof value === "number" || typeof value === "string" || typeof value === "boolean" || value instanceof ArrayBuffer || value instanceof Uint8Array) return value;
  throw new Error(`Unsupported d1 param value at index ${index}: ${value}`);
}
var RpcD1PreparedStatement = class _RpcD1PreparedStatement {
  channel;
  d1DatabaseUuid;
  query;
  params;
  constructor(channel, { query, d1DatabaseUuid, params }) {
    this.channel = channel;
    this.d1DatabaseUuid = d1DatabaseUuid;
    this.query = query;
    this.params = params;
  }
  bind(...values) {
    const { channel, query, d1DatabaseUuid } = this;
    const params = values.map(checkParamValue);
    return new _RpcD1PreparedStatement(channel, { query, d1DatabaseUuid, params });
  }
  async first(column) {
    const { d1DatabaseUuid, query, params } = this;
    const request = { method: "first", d1DatabaseUuid, column, query, params };
    return await this.channel.sendRequest("d1", request, (data) => {
      if ("error" in data) throw new Error(data.error);
      return data.result;
    });
  }
  async all() {
    const { d1DatabaseUuid, query, params } = this;
    const request = { method: "all", d1DatabaseUuid, query, params };
    return await this.channel.sendRequest("d1", request, (data) => {
      if ("error" in data) throw new Error(data.error);
      return data.result;
    });
  }
  async run() {
    return await this.all();
  }
  async raw({ columnNames = false } = {}) {
    const { d1DatabaseUuid, query, params } = this;
    const request = { method: "raw", d1DatabaseUuid, query, params, columnNames };
    return await this.channel.sendRequest("d1", request, (data) => {
      if ("error" in data) throw new Error(data.error);
      return data.result;
    });
  }
  static toPacked(statement) {
    const { query, params } = statement;
    return { query, params };
  }
};

// https://raw.githubusercontent.com/skymethod/denoflare/f414afa279f0ab095eb40505f51afa913adc2d7e/common/noop_email_sender.ts
var NoopEmailSender = class _NoopEmailSender {
  destinationAddresses;
  constructor(destinationAddresses) {
    this.destinationAddresses = destinationAddresses;
  }
  send(message) {
    console.log(`NoopEmailSender.send: ${JSON.stringify(message)}`);
    return Promise.resolve();
  }
  static provider = (destinationAddresses) => new _NoopEmailSender(destinationAddresses);
};

// https://raw.githubusercontent.com/skymethod/denoflare/f414afa279f0ab095eb40505f51afa913adc2d7e/common/noop_queue.ts
var NoopQueue = class _NoopQueue {
  queueName;
  constructor(queueName) {
    this.queueName = queueName;
  }
  send(message, opts) {
    console.log(`NoopQueue.send(${JSON.stringify(message)}, ${JSON.stringify(opts)})`);
    return Promise.resolve();
  }
  sendBatch(messages) {
    console.log(`NoopQueue.sendBatch(${JSON.stringify(messages)})`);
    return Promise.resolve();
  }
  static provider = (queueName) => new _NoopQueue(queueName);
};

// https://raw.githubusercontent.com/skymethod/denoflare/f414afa279f0ab095eb40505f51afa913adc2d7e/common/rpc_script.ts
function addRequestHandlerForRunScript(channel) {
  channel.addRequestHandler("run-script", async (requestData) => {
    const { verbose, scriptContents, scriptType, bindings, denoVersion } = requestData;
    if (verbose) {
      RpcChannel.VERBOSE = verbose;
      ModuleWorkerExecution.VERBOSE = verbose;
      FetchUtil.VERBOSE = verbose;
      LocalWebSockets.VERBOSE = verbose;
    }
    const b = new Blob([scriptContents]);
    const u = URL.createObjectURL(b);
    let objects;
    const rpcStubWebSockets = new RpcStubWebSockets(channel);
    const rpcDurableObjectStorageProvider = makeRpcStubDurableObjectStorageProvider(channel);
    const d1DatabaseProvider = makeRpcStubD1DatabaseProvider(channel);
    const globalThisAsAny2 = globalThis;
    const bodies = new Bodies();
    globalThisAsAny2.fetch = makeFetchOverRpc(channel, denoVersion, bodies, (v) => rpcStubWebSockets.unpackWebSocket(v));
    addRequestHandlerForReadBodyChunk(channel, bodies);
    channel.addRequestHandler("worker-fetch", async (workerFetchData) => {
      const workerFetch = workerFetchData;
      const request = unpackRequest(workerFetch.packedRequest, makeBodyResolverOverRpc(channel, denoVersion));
      const response = await exec.fetch(request, workerFetch.opts);
      const responseData = await packResponse(response, bodies, (v) => rpcStubWebSockets.packWebSocket(v));
      return { data: responseData, transfer: responseData.bodyBytes ? [responseData.bodyBytes.buffer] : [] };
    });
    globalThisAsAny2.__cloudflareSocketsProvider = () => makeRpcCloudflareSockets(channel);
    const exec = await WorkerExecution.start(u, scriptType, bindings, {
      onModuleWorkerInfo: (moduleWorkerInfo) => {
        const { moduleWorkerExportedFunctions, moduleWorkerEnv } = moduleWorkerInfo;
        const storageProvider = rpcDurableObjectStorageProvider;
        objects = new LocalDurableObjects({ moduleWorkerExportedFunctions, moduleWorkerEnv, storageProvider });
      },
      globalCachesProvider: () => new NoopCfGlobalCaches(),
      webSocketPairProvider: () => rpcStubWebSockets.allocateNewWebSocketPair(),
      kvNamespaceProvider: (kvNamespace) => new RpcKVNamespace(kvNamespace, channel),
      doNamespaceProvider: (doNamespace) => {
        if (objects === void 0) return new UnimplementedDurableObjectNamespace(doNamespace);
        return objects.resolveDoNamespace(doNamespace);
      },
      r2BucketProvider: (bucketName) => new RpcR2Bucket(bucketName, channel, makeBodyResolverOverRpc(channel, denoVersion), bodies),
      analyticsEngineProvider: NoopAnalyticsEngine.provider,
      d1DatabaseProvider,
      secretKeyProvider: cryptoKeyProvider,
      emailSenderProvider: NoopEmailSender.provider,
      queueProvider: NoopQueue.provider,
      incomingRequestCfPropertiesProvider: () => makeIncomingRequestCfProperties()
    });
  });
}

// https://raw.githubusercontent.com/skymethod/denoflare/f414afa279f0ab095eb40505f51afa913adc2d7e/cli-webworker/worker.ts
(function() {
  consoleLog("worker: start");
  const rpcChannel = new RpcChannel("worker", self.postMessage.bind(self));
  self.onmessage = async function(event) {
    if (await rpcChannel.receiveMessage(event.data)) return;
    consoleLog("worker: onmessage", event.data);
  };
  self.onmessageerror = function(event) {
    consoleLog("worker: onmessageerror", event);
  };
  addRequestHandlerForRunScript(rpcChannel);
})();
/*
 * [js-sha1]{@link https://github.com/emn178/js-sha1}
 *
 * @version 0.6.0
 * @author Chen, Yi-Cyuan [emn178@gmail.com]
 * @copyright Chen, Yi-Cyuan 2014-2017
 * @license MIT
 */

Bundled https://raw.githubusercontent.com/skymethod/denoflare/f414afa279f0ab095eb40505f51afa913adc2d7e/cli-webworker/worker.ts (esbuild) in 148ms
runScript: bug.ts
{ out: "", err: "", success: true }
computeScriptContents: workerJs // ../../Library/Caches/deno/deno_esbuild/registry.npmjs.org/@trpc/server@10.45.2/node_modules/@trpc/server/dist/getCauseFromUnknown-2d66414a.mjs
function isObject(value) {
  return !!value && !Array.isArray(value) && typeof value === "object";
}
var UnknownCauseError = class extends Error {
};
function getCauseFromUnknown(cause) {
  if (cause instanceof Error) {
    return cause;
  }
  const type = typeof cause;
  if (type === "undefined" || type === "function" || cause === null) {
    return void 0;
  }
  if (type !== "object") {
    return new Error(String(cause));
  }
  if (isObject(cause)) {
    const err = new UnknownCauseError();
    for (const key in cause) {
      err[key] = cause[key];
    }
    return err;
  }
  return void 0;
}

// ../../Library/Caches/deno/deno_esbuild/registry.npmjs.org/@trpc/server@10.45.2/node_modules/@trpc/server/dist/TRPCError-98d44758.mjs
function getTRPCErrorFromUnknown(cause) {
  if (cause instanceof TRPCError) {
    return cause;
  }
  if (cause instanceof Error && cause.name === "TRPCError") {
    return cause;
  }
  const trpcError = new TRPCError({
    code: "INTERNAL_SERVER_ERROR",
    cause
  });
  if (cause instanceof Error && cause.stack) {
    trpcError.stack = cause.stack;
  }
  return trpcError;
}
var TRPCError = class extends Error {
  constructor(opts) {
    const cause = getCauseFromUnknown(opts.cause);
    const message = opts.message ?? cause?.message ?? opts.code;
    super(message, {
      cause
    });
    this.code = opts.code;
    this.name = "TRPCError";
    if (!this.cause) {
      this.cause = cause;
    }
  }
};

// ../../Library/Caches/deno/deno_esbuild/registry.npmjs.org/@trpc/server@10.45.2/node_modules/@trpc/server/dist/codes-c924c3db.mjs
function invert(obj) {
  const newObj = /* @__PURE__ */ Object.create(null);
  for (const key in obj) {
    const v = obj[key];
    newObj[v] = key;
  }
  return newObj;
}
var TRPC_ERROR_CODES_BY_KEY = {
  /**
  * Invalid JSON was received by the server.
  * An error occurred on the server while parsing the JSON text.
  */
  PARSE_ERROR: -32700,
  /**
  * The JSON sent is not a valid Request object.
  */
  BAD_REQUEST: -32600,
  // Internal JSON-RPC error
  INTERNAL_SERVER_ERROR: -32603,
  NOT_IMPLEMENTED: -32603,
  // Implementation specific errors
  UNAUTHORIZED: -32001,
  FORBIDDEN: -32003,
  NOT_FOUND: -32004,
  METHOD_NOT_SUPPORTED: -32005,
  TIMEOUT: -32008,
  CONFLICT: -32009,
  PRECONDITION_FAILED: -32012,
  PAYLOAD_TOO_LARGE: -32013,
  UNPROCESSABLE_CONTENT: -32022,
  TOO_MANY_REQUESTS: -32029,
  CLIENT_CLOSED_REQUEST: -32099
};
var TRPC_ERROR_CODES_BY_NUMBER = invert(TRPC_ERROR_CODES_BY_KEY);

// ../../Library/Caches/deno/deno_esbuild/registry.npmjs.org/@trpc/server@10.45.2/node_modules/@trpc/server/dist/index-f91d720c.mjs
var TRPC_ERROR_CODES_BY_NUMBER2 = invert(TRPC_ERROR_CODES_BY_KEY);
var JSONRPC2_TO_HTTP_CODE = {
  PARSE_ERROR: 400,
  BAD_REQUEST: 400,
  UNAUTHORIZED: 401,
  NOT_FOUND: 404,
  FORBIDDEN: 403,
  METHOD_NOT_SUPPORTED: 405,
  TIMEOUT: 408,
  CONFLICT: 409,
  PRECONDITION_FAILED: 412,
  PAYLOAD_TOO_LARGE: 413,
  UNPROCESSABLE_CONTENT: 422,
  TOO_MANY_REQUESTS: 429,
  CLIENT_CLOSED_REQUEST: 499,
  INTERNAL_SERVER_ERROR: 500,
  NOT_IMPLEMENTED: 501
};
function getStatusCodeFromKey(code) {
  return JSONRPC2_TO_HTTP_CODE[code] ?? 500;
}
function getHTTPStatusCode(json) {
  const arr = Array.isArray(json) ? json : [
    json
  ];
  const httpStatuses = new Set(arr.map((res) => {
    if ("error" in res) {
      const data = res.error.data;
      if (typeof data.httpStatus === "number") {
        return data.httpStatus;
      }
      const code = TRPC_ERROR_CODES_BY_NUMBER2[res.error.code];
      return getStatusCodeFromKey(code);
    }
    return 200;
  }));
  if (httpStatuses.size !== 1) {
    return 207;
  }
  const httpStatus = httpStatuses.values().next().value;
  return httpStatus;
}
function getHTTPStatusCodeFromError(error) {
  return getStatusCodeFromKey(error.code);
}
var noop = () => {
};
function createInnerProxy(callback, path) {
  const proxy = new Proxy(noop, {
    get(_obj, key) {
      if (typeof key !== "string" || key === "then") {
        return void 0;
      }
      return createInnerProxy(callback, [
        ...path,
        key
      ]);
    },
    apply(_1, _2, args) {
      const isApply = path[path.length - 1] === "apply";
      return callback({
        args: isApply ? args.length >= 2 ? args[1] : [] : args,
        path: isApply ? path.slice(0, -1) : path
      });
    }
  });
  return proxy;
}
var createRecursiveProxy = (callback) => createInnerProxy(callback, []);
var createFlatProxy = (callback) => {
  return new Proxy(noop, {
    get(_obj, name) {
      if (typeof name !== "string" || name === "then") {
        return void 0;
      }
      return callback(name);
    }
  });
};

// ../../Library/Caches/deno/deno_esbuild/registry.npmjs.org/@trpc/server@10.45.2/node_modules/@trpc/server/dist/config-d5fdbd39.mjs
function getDataTransformer(transformer) {
  if ("input" in transformer) {
    return transformer;
  }
  return {
    input: transformer,
    output: transformer
  };
}
var defaultTransformer = {
  _default: true,
  input: {
    serialize: (obj) => obj,
    deserialize: (obj) => obj
  },
  output: {
    serialize: (obj) => obj,
    deserialize: (obj) => obj
  }
};
var defaultFormatter = ({ shape }) => {
  return shape;
};
function omitPrototype(obj) {
  return Object.assign(/* @__PURE__ */ Object.create(null), obj);
}
var procedureTypes = [
  "query",
  "mutation",
  "subscription"
];
function isRouter(procedureOrRouter) {
  return "router" in procedureOrRouter._def;
}
var emptyRouter = {
  _ctx: null,
  _errorShape: null,
  _meta: null,
  queries: {},
  mutations: {},
  subscriptions: {},
  errorFormatter: defaultFormatter,
  transformer: defaultTransformer
};
var reservedWords = [
  /**
  * Then is a reserved word because otherwise we can't return a promise that returns a Proxy
  * since JS will think that `.then` is something that exists
  */
  "then"
];
function createRouterFactory(config) {
  return function createRouterInner(procedures) {
    const reservedWordsUsed = new Set(Object.keys(procedures).filter((v) => reservedWords.includes(v)));
    if (reservedWordsUsed.size > 0) {
      throw new Error("Reserved words used in `router({})` call: " + Array.from(reservedWordsUsed).join(", "));
    }
    const routerProcedures = omitPrototype({});
    function recursiveGetPaths(procedures2, path = "") {
      for (const [key, procedureOrRouter] of Object.entries(procedures2 ?? {})) {
        const newPath = `${path}${key}`;
        if (isRouter(procedureOrRouter)) {
          recursiveGetPaths(procedureOrRouter._def.procedures, `${newPath}.`);
          continue;
        }
        if (routerProcedures[newPath]) {
          throw new Error(`Duplicate key: ${newPath}`);
        }
        routerProcedures[newPath] = procedureOrRouter;
      }
    }
    recursiveGetPaths(procedures);
    const _def = {
      _config: config,
      router: true,
      procedures: routerProcedures,
      ...emptyRouter,
      record: procedures,
      queries: Object.entries(routerProcedures).filter((pair) => pair[1]._def.query).reduce((acc, [key, val]) => ({
        ...acc,
        [key]: val
      }), {}),
      mutations: Object.entries(routerProcedures).filter((pair) => pair[1]._def.mutation).reduce((acc, [key, val]) => ({
        ...acc,
        [key]: val
      }), {}),
      subscriptions: Object.entries(routerProcedures).filter((pair) => pair[1]._def.subscription).reduce((acc, [key, val]) => ({
        ...acc,
        [key]: val
      }), {})
    };
    const router2 = {
      ...procedures,
      _def,
      createCaller(ctx) {
        return createCallerFactory()(router2)(ctx);
      },
      getErrorShape(opts) {
        const { path, error } = opts;
        const { code } = opts.error;
        const shape = {
          message: error.message,
          code: TRPC_ERROR_CODES_BY_KEY[code],
          data: {
            code,
            httpStatus: getHTTPStatusCodeFromError(error)
          }
        };
        if (config.isDev && typeof opts.error.stack === "string") {
          shape.data.stack = opts.error.stack;
        }
        if (typeof path === "string") {
          shape.data.path = path;
        }
        return this._def._config.errorFormatter({
          ...opts,
          shape
        });
      }
    };
    return router2;
  };
}
function callProcedure(opts) {
  const { type, path } = opts;
  if (!(path in opts.procedures) || !opts.procedures[path]?._def[type]) {
    throw new TRPCError({
      code: "NOT_FOUND",
      message: `No "${type}"-procedure on path "${path}"`
    });
  }
  const procedure = opts.procedures[path];
  return procedure(opts);
}
function createCallerFactory() {
  return function createCallerInner(router2) {
    const def = router2._def;
    return function createCaller(ctx) {
      const proxy = createRecursiveProxy(({ path, args }) => {
        if (path.length === 1 && procedureTypes.includes(path[0])) {
          return callProcedure({
            procedures: def.procedures,
            path: args[0],
            rawInput: args[1],
            ctx,
            type: path[0]
          });
        }
        const fullPath = path.join(".");
        const procedure = def.procedures[fullPath];
        let type = "query";
        if (procedure._def.mutation) {
          type = "mutation";
        } else if (procedure._def.subscription) {
          type = "subscription";
        }
        return procedure({
          path: fullPath,
          rawInput: args[0],
          ctx,
          type
        });
      });
      return proxy;
    };
  };
}
var isServerDefault = typeof window === "undefined" || "Deno" in window || globalThis.process?.env?.NODE_ENV === "test" || !!globalThis.process?.env?.JEST_WORKER_ID || !!globalThis.process?.env?.VITEST_WORKER_ID;

// ../../Library/Caches/deno/deno_esbuild/registry.npmjs.org/@trpc/server@10.45.2/node_modules/@trpc/server/dist/index.mjs
function getParseFn(procedureParser) {
  const parser = procedureParser;
  if (typeof parser === "function") {
    return parser;
  }
  if (typeof parser.parseAsync === "function") {
    return parser.parseAsync.bind(parser);
  }
  if (typeof parser.parse === "function") {
    return parser.parse.bind(parser);
  }
  if (typeof parser.validateSync === "function") {
    return parser.validateSync.bind(parser);
  }
  if (typeof parser.create === "function") {
    return parser.create.bind(parser);
  }
  if (typeof parser.assert === "function") {
    return (value) => {
      parser.assert(value);
      return value;
    };
  }
  throw new Error("Could not find a validator fn");
}
function mergeWithoutOverrides(obj1, ...objs) {
  const newObj = Object.assign(/* @__PURE__ */ Object.create(null), obj1);
  for (const overrides of objs) {
    for (const key in overrides) {
      if (key in newObj && newObj[key] !== overrides[key]) {
        throw new Error(`Duplicate key ${key}`);
      }
      newObj[key] = overrides[key];
    }
  }
  return newObj;
}
function createMiddlewareFactory() {
  function createMiddlewareInner(middlewares) {
    return {
      _middlewares: middlewares,
      unstable_pipe(middlewareBuilderOrFn) {
        const pipedMiddleware = "_middlewares" in middlewareBuilderOrFn ? middlewareBuilderOrFn._middlewares : [
          middlewareBuilderOrFn
        ];
        return createMiddlewareInner([
          ...middlewares,
          ...pipedMiddleware
        ]);
      }
    };
  }
  function createMiddleware(fn) {
    return createMiddlewareInner([
      fn
    ]);
  }
  return createMiddleware;
}
function isPlainObject(obj) {
  return obj && typeof obj === "object" && !Array.isArray(obj);
}
function createInputMiddleware(parse) {
  const inputMiddleware = async ({ next, rawInput, input }) => {
    let parsedInput;
    try {
      parsedInput = await parse(rawInput);
    } catch (cause) {
      throw new TRPCError({
        code: "BAD_REQUEST",
        cause
      });
    }
    const combinedInput = isPlainObject(input) && isPlainObject(parsedInput) ? {
      ...input,
      ...parsedInput
    } : parsedInput;
    return next({
      input: combinedInput
    });
  };
  inputMiddleware._type = "input";
  return inputMiddleware;
}
function createOutputMiddleware(parse) {
  const outputMiddleware = async ({ next }) => {
    const result = await next();
    if (!result.ok) {
      return result;
    }
    try {
      const data = await parse(result.data);
      return {
        ...result,
        data
      };
    } catch (cause) {
      throw new TRPCError({
        message: "Output validation failed",
        code: "INTERNAL_SERVER_ERROR",
        cause
      });
    }
  };
  outputMiddleware._type = "output";
  return outputMiddleware;
}
var middlewareMarker = "middlewareMarker";
function createNewBuilder(def1, def2) {
  const { middlewares = [], inputs, meta, ...rest } = def2;
  return createBuilder({
    ...mergeWithoutOverrides(def1, rest),
    inputs: [
      ...def1.inputs,
      ...inputs ?? []
    ],
    middlewares: [
      ...def1.middlewares,
      ...middlewares
    ],
    meta: def1.meta && meta ? {
      ...def1.meta,
      ...meta
    } : meta ?? def1.meta
  });
}
function createBuilder(initDef = {}) {
  const _def = {
    inputs: [],
    middlewares: [],
    ...initDef
  };
  return {
    _def,
    input(input) {
      const parser = getParseFn(input);
      return createNewBuilder(_def, {
        inputs: [
          input
        ],
        middlewares: [
          createInputMiddleware(parser)
        ]
      });
    },
    output(output) {
      const parseOutput = getParseFn(output);
      return createNewBuilder(_def, {
        output,
        middlewares: [
          createOutputMiddleware(parseOutput)
        ]
      });
    },
    meta(meta) {
      return createNewBuilder(_def, {
        meta
      });
    },
    /**
    * @deprecated
    * This functionality is deprecated and will be removed in the next major version.
    */
    unstable_concat(builder) {
      return createNewBuilder(_def, builder._def);
    },
    use(middlewareBuilderOrFn) {
      const middlewares = "_middlewares" in middlewareBuilderOrFn ? middlewareBuilderOrFn._middlewares : [
        middlewareBuilderOrFn
      ];
      return createNewBuilder(_def, {
        middlewares
      });
    },
    query(resolver) {
      return createResolver({
        ..._def,
        query: true
      }, resolver);
    },
    mutation(resolver) {
      return createResolver({
        ..._def,
        mutation: true
      }, resolver);
    },
    subscription(resolver) {
      return createResolver({
        ..._def,
        subscription: true
      }, resolver);
    }
  };
}
function createResolver(_def, resolver) {
  const finalBuilder = createNewBuilder(_def, {
    resolver,
    middlewares: [
      async function resolveMiddleware(opts) {
        const data = await resolver(opts);
        return {
          marker: middlewareMarker,
          ok: true,
          data,
          ctx: opts.ctx
        };
      }
    ]
  });
  return createProcedureCaller(finalBuilder._def);
}
var codeblock = `
This is a client-only function.
If you want to call this function on the server, see https://trpc.io/docs/server/server-side-calls
`.trim();
function createProcedureCaller(_def) {
  const procedure = async function resolve(opts) {
    if (!opts || !("rawInput" in opts)) {
      throw new Error(codeblock);
    }
    const callRecursive = async (callOpts = {
      index: 0,
      ctx: opts.ctx
    }) => {
      try {
        const middleware = _def.middlewares[callOpts.index];
        const result2 = await middleware({
          ctx: callOpts.ctx,
          type: opts.type,
          path: opts.path,
          rawInput: callOpts.rawInput ?? opts.rawInput,
          meta: _def.meta,
          input: callOpts.input,
          next(_nextOpts) {
            const nextOpts = _nextOpts;
            return callRecursive({
              index: callOpts.index + 1,
              ctx: nextOpts && "ctx" in nextOpts ? {
                ...callOpts.ctx,
                ...nextOpts.ctx
              } : callOpts.ctx,
              input: nextOpts && "input" in nextOpts ? nextOpts.input : callOpts.input,
              rawInput: nextOpts && "rawInput" in nextOpts ? nextOpts.rawInput : callOpts.rawInput
            });
          }
        });
        return result2;
      } catch (cause) {
        return {
          ok: false,
          error: getTRPCErrorFromUnknown(cause),
          marker: middlewareMarker
        };
      }
    };
    const result = await callRecursive();
    if (!result) {
      throw new TRPCError({
        code: "INTERNAL_SERVER_ERROR",
        message: "No result from middlewares - did you forget to `return next()`?"
      });
    }
    if (!result.ok) {
      throw result.error;
    }
    return result.data;
  };
  procedure._def = _def;
  procedure.meta = _def.meta;
  return procedure;
}
function mergeRouters(...routerList) {
  const record = mergeWithoutOverrides({}, ...routerList.map((r) => r._def.record));
  const errorFormatter = routerList.reduce((currentErrorFormatter, nextRouter) => {
    if (nextRouter._def._config.errorFormatter && nextRouter._def._config.errorFormatter !== defaultFormatter) {
      if (currentErrorFormatter !== defaultFormatter && currentErrorFormatter !== nextRouter._def._config.errorFormatter) {
        throw new Error("You seem to have several error formatters");
      }
      return nextRouter._def._config.errorFormatter;
    }
    return currentErrorFormatter;
  }, defaultFormatter);
  const transformer = routerList.reduce((prev, current) => {
    if (current._def._config.transformer && current._def._config.transformer !== defaultTransformer) {
      if (prev !== defaultTransformer && prev !== current._def._config.transformer) {
        throw new Error("You seem to have several transformers");
      }
      return current._def._config.transformer;
    }
    return prev;
  }, defaultTransformer);
  const router2 = createRouterFactory({
    errorFormatter,
    transformer,
    isDev: routerList.some((r) => r._def._config.isDev),
    allowOutsideOfServer: routerList.some((r) => r._def._config.allowOutsideOfServer),
    isServer: routerList.some((r) => r._def._config.isServer),
    $types: routerList[0]?._def._config.$types
  })(record);
  return router2;
}
var TRPCBuilder = class _TRPCBuilder {
  context() {
    return new _TRPCBuilder();
  }
  meta() {
    return new _TRPCBuilder();
  }
  create(options) {
    return createTRPCInner()(options);
  }
};
var initTRPC = new TRPCBuilder();
function createTRPCInner() {
  return function initTRPCInner(runtime) {
    const errorFormatter = runtime?.errorFormatter ?? defaultFormatter;
    const transformer = getDataTransformer(runtime?.transformer ?? defaultTransformer);
    const config = {
      transformer,
      isDev: runtime?.isDev ?? globalThis.process?.env?.NODE_ENV !== "production",
      allowOutsideOfServer: runtime?.allowOutsideOfServer ?? false,
      errorFormatter,
      isServer: runtime?.isServer ?? isServerDefault,
      /**
      * @internal
      */
      $types: createFlatProxy((key) => {
        throw new Error(`Tried to access "$types.${key}" which is not available at runtime`);
      })
    };
    {
      const isServer = runtime?.isServer ?? isServerDefault;
      if (!isServer && runtime?.allowOutsideOfServer !== true) {
        throw new Error(`You're trying to use @trpc/server in a non-server environment. This is not supported by default.`);
      }
    }
    return {
      /**
      * These are just types, they can't be used
      * @internal
      */
      _config: config,
      /**
      * Builder object for creating procedures
      * @see https://trpc.io/docs/server/procedures
      */
      procedure: createBuilder({
        meta: runtime?.defaultMeta
      }),
      /**
      * Create reusable middlewares
      * @see https://trpc.io/docs/server/middlewares
      */
      middleware: createMiddlewareFactory(),
      /**
      * Create a router
      * @see https://trpc.io/docs/server/routers
      */
      router: createRouterFactory(config),
      /**
      * Merge Routers
      * @see https://trpc.io/docs/server/merging-routers
      */
      mergeRouters,
      /**
      * Create a server-side caller for a router
      * @see https://trpc.io/docs/server/server-side-calls
      */
      createCallerFactory: createCallerFactory()
    };
  };
}

// ../../Library/Caches/deno/deno_esbuild/registry.npmjs.org/@trpc/server@10.45.2/node_modules/@trpc/server/dist/transformTRPCResponse-1153b421.mjs
function getErrorShape(opts) {
  const { path, error, config } = opts;
  const { code } = opts.error;
  const shape = {
    message: error.message,
    code: TRPC_ERROR_CODES_BY_KEY[code],
    data: {
      code,
      httpStatus: getHTTPStatusCodeFromError(error)
    }
  };
  if (config.isDev && typeof opts.error.stack === "string") {
    shape.data.stack = opts.error.stack;
  }
  if (typeof path === "string") {
    shape.data.path = path;
  }
  return config.errorFormatter({
    ...opts,
    shape
  });
}
function transformTRPCResponseItem(config, item) {
  if ("error" in item) {
    return {
      ...item,
      error: config.transformer.output.serialize(item.error)
    };
  }
  if ("data" in item.result) {
    return {
      ...item,
      result: {
        ...item.result,
        data: config.transformer.output.serialize(item.result.data)
      }
    };
  }
  return item;
}
function transformTRPCResponse(config, itemOrItems) {
  return Array.isArray(itemOrItems) ? itemOrItems.map((item) => transformTRPCResponseItem(config, item)) : transformTRPCResponseItem(config, itemOrItems);
}

// ../../Library/Caches/deno/deno_esbuild/registry.npmjs.org/@trpc/server@10.45.2/node_modules/@trpc/server/dist/contentType-9fd995d3.mjs
function getRawProcedureInputOrThrow(opts) {
  const { req } = opts;
  try {
    if (req.method === "GET") {
      if (!req.query.has("input")) {
        return void 0;
      }
      const raw = req.query.get("input");
      return JSON.parse(raw);
    }
    if (!opts.preprocessedBody && typeof req.body === "string") {
      return req.body.length === 0 ? void 0 : JSON.parse(req.body);
    }
    return req.body;
  } catch (cause) {
    throw new TRPCError({
      code: "PARSE_ERROR",
      cause
    });
  }
}
var deserializeInputValue = (rawValue, transformer) => {
  return typeof rawValue !== "undefined" ? transformer.input.deserialize(rawValue) : rawValue;
};
var getJsonContentTypeInputs = (opts) => {
  const rawInput = getRawProcedureInputOrThrow(opts);
  const transformer = opts.router._def._config.transformer;
  if (!opts.isBatchCall) {
    return {
      0: deserializeInputValue(rawInput, transformer)
    };
  }
  if (rawInput == null || typeof rawInput !== "object" || Array.isArray(rawInput)) {
    throw new TRPCError({
      code: "BAD_REQUEST",
      message: '"input" needs to be an object when doing a batch call'
    });
  }
  const input = {};
  for (const key in rawInput) {
    const k = key;
    const rawValue = rawInput[k];
    const value = deserializeInputValue(rawValue, transformer);
    input[k] = value;
  }
  return input;
};

// ../../Library/Caches/deno/deno_esbuild/registry.npmjs.org/@trpc/server@10.45.2/node_modules/@trpc/server/dist/resolveHTTPResponse-2fc435bb.mjs
var HTTP_METHOD_PROCEDURE_TYPE_MAP = {
  GET: "query",
  POST: "mutation"
};
var fallbackContentTypeHandler = {
  getInputs: getJsonContentTypeInputs
};
function initResponse(initOpts) {
  const { ctx, paths, type, responseMeta, untransformedJSON, errors = [] } = initOpts;
  let status = untransformedJSON ? getHTTPStatusCode(untransformedJSON) : 200;
  const headers = {
    "Content-Type": "application/json"
  };
  const eagerGeneration = !untransformedJSON;
  const data = eagerGeneration ? [] : Array.isArray(untransformedJSON) ? untransformedJSON : [
    untransformedJSON
  ];
  const meta = responseMeta?.({
    ctx,
    paths,
    type,
    data,
    errors,
    eagerGeneration
  }) ?? {};
  for (const [key, value] of Object.entries(meta.headers ?? {})) {
    headers[key] = value;
  }
  if (meta.status) {
    status = meta.status;
  }
  return {
    status,
    headers
  };
}
async function inputToProcedureCall(procedureOpts) {
  const { opts, ctx, type, input, path } = procedureOpts;
  try {
    const data = await callProcedure({
      procedures: opts.router._def.procedures,
      path,
      rawInput: input,
      ctx,
      type
    });
    return {
      result: {
        data
      }
    };
  } catch (cause) {
    const error = getTRPCErrorFromUnknown(cause);
    opts.onError?.({
      error,
      path,
      input,
      ctx,
      type,
      req: opts.req
    });
    return {
      error: getErrorShape({
        config: opts.router._def._config,
        error,
        type,
        path,
        input,
        ctx
      })
    };
  }
}
function caughtErrorToData(cause, errorOpts) {
  const { router: router2, req, onError } = errorOpts.opts;
  const error = getTRPCErrorFromUnknown(cause);
  onError?.({
    error,
    path: errorOpts.path,
    input: errorOpts.input,
    ctx: errorOpts.ctx,
    type: errorOpts.type,
    req
  });
  const untransformedJSON = {
    error: getErrorShape({
      config: router2._def._config,
      error,
      type: errorOpts.type,
      path: errorOpts.path,
      input: errorOpts.input,
      ctx: errorOpts.ctx
    })
  };
  const transformedJSON = transformTRPCResponse(router2._def._config, untransformedJSON);
  const body = JSON.stringify(transformedJSON);
  return {
    error,
    untransformedJSON,
    body
  };
}
async function resolveHTTPResponse(opts) {
  const { router: router2, req, unstable_onHead, unstable_onChunk } = opts;
  if (req.method === "HEAD") {
    const headResponse = {
      status: 204
    };
    unstable_onHead?.(headResponse, false);
    unstable_onChunk?.([
      -1,
      ""
    ]);
    return headResponse;
  }
  const contentTypeHandler = opts.contentTypeHandler ?? fallbackContentTypeHandler;
  const batchingEnabled = opts.batching?.enabled ?? true;
  const type = HTTP_METHOD_PROCEDURE_TYPE_MAP[req.method] ?? "unknown";
  let ctx = void 0;
  let paths;
  const isBatchCall = !!req.query.get("batch");
  const isStreamCall = isBatchCall && unstable_onHead && unstable_onChunk && req.headers["trpc-batch-mode"] === "stream";
  try {
    ctx = await opts.createContext();
    if (opts.error) {
      throw opts.error;
    }
    if (isBatchCall && !batchingEnabled) {
      throw new Error(`Batching is not enabled on the server`);
    }
    if (type === "subscription") {
      throw new TRPCError({
        message: "Subscriptions should use wsLink",
        code: "METHOD_NOT_SUPPORTED"
      });
    }
    if (type === "unknown") {
      throw new TRPCError({
        message: `Unexpected request method ${req.method}`,
        code: "METHOD_NOT_SUPPORTED"
      });
    }
    const inputs = await contentTypeHandler.getInputs({
      isBatchCall,
      req,
      router: router2,
      preprocessedBody: opts.preprocessedBody ?? false
    });
    paths = isBatchCall ? decodeURIComponent(opts.path).split(",") : [
      opts.path
    ];
    const promises = paths.map((path, index) => inputToProcedureCall({
      opts,
      ctx,
      type,
      input: inputs[index],
      path
    }));
    if (!isStreamCall) {
      const untransformedJSON = await Promise.all(promises);
      const errors = untransformedJSON.flatMap((response) => "error" in response ? [
        response.error
      ] : []);
      const headResponse1 = initResponse({
        ctx,
        paths,
        type,
        responseMeta: opts.responseMeta,
        untransformedJSON,
        errors
      });
      unstable_onHead?.(headResponse1, false);
      const result = isBatchCall ? untransformedJSON : untransformedJSON[0];
      const transformedJSON = transformTRPCResponse(router2._def._config, result);
      const body = JSON.stringify(transformedJSON);
      unstable_onChunk?.([
        -1,
        body
      ]);
      return {
        status: headResponse1.status,
        headers: headResponse1.headers,
        body
      };
    }
    const headResponse2 = initResponse({
      ctx,
      paths,
      type,
      responseMeta: opts.responseMeta
    });
    unstable_onHead(headResponse2, true);
    const indexedPromises = new Map(promises.map((promise, index) => [
      index,
      promise.then((r) => [
        index,
        r
      ])
    ]));
    for (const _ of paths) {
      const [index, untransformedJSON1] = await Promise.race(indexedPromises.values());
      indexedPromises.delete(index);
      try {
        const transformedJSON1 = transformTRPCResponse(router2._def._config, untransformedJSON1);
        const body1 = JSON.stringify(transformedJSON1);
        unstable_onChunk([
          index,
          body1
        ]);
      } catch (cause) {
        const path = paths[index];
        const input = inputs[index];
        const { body: body2 } = caughtErrorToData(cause, {
          opts,
          ctx,
          type,
          path,
          input
        });
        unstable_onChunk([
          index,
          body2
        ]);
      }
    }
    return;
  } catch (cause1) {
    const { error, untransformedJSON: untransformedJSON2, body: body3 } = caughtErrorToData(cause1, {
      opts,
      ctx,
      type
    });
    const headResponse3 = initResponse({
      ctx,
      paths,
      type,
      responseMeta: opts.responseMeta,
      untransformedJSON: untransformedJSON2,
      errors: [
        error
      ]
    });
    unstable_onHead?.(headResponse3, false);
    unstable_onChunk?.([
      -1,
      body3
    ]);
    return {
      status: headResponse3.status,
      headers: headResponse3.headers,
      body: body3
    };
  }
}

// ../../Library/Caches/deno/deno_esbuild/registry.npmjs.org/@trpc/server@10.45.2/node_modules/@trpc/server/dist/batchStreamFormatter-fc1ffb26.mjs
function getBatchStreamFormatter() {
  let first = true;
  function format(index, string) {
    const prefix = first ? "{" : ",";
    first = false;
    return `${prefix}"${index}":${string}
`;
  }
  format.end = () => "}";
  return format;
}

// ../../Library/Caches/deno/deno_esbuild/registry.npmjs.org/@trpc/server@10.45.2/node_modules/@trpc/server/dist/toURL-8f0ea228.mjs
function toURL(urlOrPathname) {
  const url = urlOrPathname.startsWith("/") ? `http://127.0.0.1${urlOrPathname}` : urlOrPathname;
  return new URL(url);
}

// ../../Library/Caches/deno/deno_esbuild/registry.npmjs.org/@trpc/server@10.45.2/node_modules/@trpc/server/dist/adapters/fetch/index.mjs
var trimSlashes = (path) => {
  path = path.startsWith("/") ? path.slice(1) : path;
  path = path.endsWith("/") ? path.slice(0, -1) : path;
  return path;
};
async function fetchRequestHandler(opts) {
  const resHeaders = new Headers();
  const createContext = async () => {
    return opts.createContext?.({
      req: opts.req,
      resHeaders
    });
  };
  const url = toURL(opts.req.url);
  const pathname = trimSlashes(url.pathname);
  const endpoint = trimSlashes(opts.endpoint);
  const path = trimSlashes(pathname.slice(endpoint.length));
  const req = {
    query: url.searchParams,
    method: opts.req.method,
    headers: Object.fromEntries(opts.req.headers),
    body: opts.req.headers.get("content-type")?.startsWith("application/json") ? await opts.req.text() : ""
  };
  let resolve;
  const promise = new Promise((r) => resolve = r);
  let status = 200;
  let isStream = false;
  let controller;
  let encoder;
  let formatter;
  const unstable_onHead = (head, isStreaming) => {
    for (const [key, value] of Object.entries(head.headers ?? {})) {
      if (typeof value === "undefined") {
        continue;
      }
      if (typeof value === "string") {
        resHeaders.set(key, value);
        continue;
      }
      for (const v of value) {
        resHeaders.append(key, v);
      }
    }
    status = head.status;
    if (isStreaming) {
      resHeaders.set("Transfer-Encoding", "chunked");
      resHeaders.append("Vary", "trpc-batch-mode");
      const stream = new ReadableStream({
        start(c) {
          controller = c;
        }
      });
      const response = new Response(stream, {
        status,
        headers: resHeaders
      });
      resolve(response);
      encoder = new TextEncoder();
      formatter = getBatchStreamFormatter();
      isStream = true;
    }
  };
  const unstable_onChunk = ([index, string]) => {
    if (index === -1) {
      const response = new Response(string || null, {
        status,
        headers: resHeaders
      });
      resolve(response);
    } else {
      controller.enqueue(encoder.encode(formatter(index, string)));
    }
  };
  resolveHTTPResponse({
    req,
    createContext,
    path,
    router: opts.router,
    batching: opts.batching,
    responseMeta: opts.responseMeta,
    onError(o) {
      opts?.onError?.({
        ...o,
        req: opts.req
      });
    },
    unstable_onHead,
    unstable_onChunk
  }).then(() => {
    if (isStream) {
      controller.enqueue(encoder.encode(formatter.end()));
      controller.close();
    }
  }).catch(() => {
    if (isStream) {
      controller.close();
    }
  });
  return promise;
}

// bug.ts
var t = initTRPC.create();
var router = t.router;
var publicProcedure = t.procedure;
var appRouter = router({
  hello: publicProcedure.query(() => "hi")
});
var bug_default = {
  async fetch(request) {
    return fetchRequestHandler({
      endpoint: "/trpc",
      req: request,
      router: appRouter,
      createContext: () => ({})
    });
  }
};
export {
  bug_default as default
};

</details>
