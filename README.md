# `demodel`

Easily boost the speed of pulling your models and datasets from various of inference runtimes. (e.g. [🤗 HuggingFace](https://huggingface.co/), [🐫 Ollama](https://ollama.com/), [vLLM](https://vllm.ai/), and more!)

- Out of the mind when dealing with the slow speed from the internet when pulling models and datasets?
- Already downloaded the model or dataset in another cluster or node, maybe Homelab server, but cannot share them easily?
- You got poor connection to HuggingFace or Ollama but got friends locally with models already?
- You want to serve your models and datasets to your friends locally?

`demodel` here to rescue!

## Features

Out of the box support for:

- [🤗 `huggingface-cli`](https://huggingface.co/docs/huggingface_hub/cli)
- [🤗 `transformers`](https://huggingface.co/docs/transformers/en/index)
- [Ollama](https://ollama.com/)
- [🤗 `transformers.js`](https://huggingface.co/docs/transformers.js/en/index) (both Browser and Node.js)
- [vLLM](https://github.com/vllm-project/vllm)
- [SGLang](https://github.com/sgl-project/sglang)

## Getting Started

For `pixi.sh` users, `unable to get local issuer certificate` error may appear when proxying using `demodel`:

```
requests.exceptions.SSLError: (MaxRetryError("HTTPSConnectionPool(host='huggingface.co', port=443): Max retries exceeded with url: /api/whoami-v2 (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1028)')))"), '(Request ID: <deducted>)')
```

To check which SSL path is used by `huggingface-cli` or other Python packages, do this:

```bash
$ python -c "import ssl; print(ssl.get_default_verify_paths())"
DefaultVerifyPaths(cafile='/home/neko/.pixi/envs/python/ssl/cert.pem', capath='/home/neko/.pixi/envs/python/ssl/certs', openssl_cafile_env='SSL_CERT_FILE', openssl_cafile='/home/neko/.pixi/envs/python/ssl/cert.pem', openssl_capath_env='SSL_CERT_DIR', openssl_capath='/home/neko/.pixi/envs/python/ssl/certs')
$ python -c "import certifi; print(certifi.where())"
/home/neko/.pixi/envs/python/lib/python3.13/site-packages/certifi/cacert.pem

$ demodel export-ca --for python-ssl --for python-certifi
```

If you are experiencing the same issue with `openssl` too...

```bash
# check the OpenSSL version with directory
$ openssl version -d
OPENSSLDIR: "/home/neko/.pixi/envs/python/ssl"

# if .pixi appeared, you can use the same command as above
$ demodel export-ca --for openssl
```

## Acknowledgement

- [`boring`](https://github.com/cloudflare/boring)
- [Why BoringSSL?](https://github.com/sfackler/rust-openssl/issues/1519#issue-984198410)
- [Oxy is Cloudflare's Rust-based next generation proxy framework](https://blog.cloudflare.com/introducing-oxy/)
