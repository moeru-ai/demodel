# Contributing to Demodel

Welcome! It's glad to have you here.

## Prerequisites

- Cargo 1.79.0 or higher

## Procedures

```shell
git clone https://github.com/moeru-ai/demodel.git
cd demodel
cargo build
```

```shell
RUST_LOG=debug cargo run ./src/main.rs
```

You can now send the request through either `curl` or `ollama` and get them proxied.

### `curl`

#### Request to Ollama

```shell
curl -v -x http://127.0.0.1:3128 https://registry.ollama.ai:443/v2/library/nomic-embed-text/manifests/latest
```

#### Request to Hugging Face

```shell
curl -v -x http://127.0.0.1:3128 https://huggingface.co
```

### Ollama

You will first need to start the ollama server with `HTTP_PROXY` and `HTTPS_PROXY` environment variables set:

```shell
HTTP_PROXY=http://127.0.0.1:3128 HTTPS_PROXY=http://127.0.0.1:3128 ollama start
```

And open up another terminal/session to ask Ollama pull a model:

```shell
ollama pull nomic-embed-text
```

Your request will be proxied and cached, automatically, magically.

## Caching mechanism

> The following response here cached was a request to `https://registry.ollama.ai:443/v2/library/nomic-embed-text/manifests/latest`.
>
> The expected file content should be a valid JSON object.

When working with the cached files, you may find that the cached file may appear in result like this:

```shell
$ cat .cache/1b8c2ef6c820e0c0
��ˎ1@��)�e�w�� �r9c�G���Q�!��������j�<�ʟ�}�̌'�j���rQ3\�.|����թ��M���q=z���O+o��N7��u�9ٷ��f~��ە���W>�t�6��u\�l�3c�����S���}jY��"*�Q��)K
�$�ڪH��\}3'3�5�G����/z
                      3�7s_^�7nݫ.h����g�F>�'���E��(�%'TZԢ
}�]�-[��$�,Q.�                                             ͂
            au6�Đ":,�(G�YUi.T���`ֺ@�B]��u<2�g��+>
                                                �in�m�1� %�%�HtT�$
                                                                  ��_�?���gX�
```

But don't worry, we can use `xxd` to inspect the actual content of the file in hex format:

```shell
$ xxd .cache/1b8c2ef6c820e0c0
00000000: 1f8b 0800 0000 0000 0003 94ce cb8e 1331  ...............1
00000010: 1040 d17f f196 a829 971f 65f7 778c d820  .@.....)..e.w..
00000020: 16e5 7239 63e8 47d4 0e91 8651 fe1d 21c1  ..r9c.G....Q..!.
00000030: b089 10b3 bd8b abf3 6a86 3ceb ca9f f418  ........j.<.....
00000040: 7ddf cc8c 27b3 6aed fcf4 7251 331b be5c  }...'.j...rQ3..\
00000050: 962e 7ced fbf6 f1b6 d5a9 eef2 4d8f a9f6  ..|.........M...
00000060: 713d 7af9 feab 4f2b 6fbd e9b8 4e37 fcf0  q=z...O+o...N7..
00000070: 75ec 9b39 19d9 b7d6 cf66 7efd 9f99 ecdb  u..9.....f~.....
00000080: 95fb a6c7 d457 3eeb 74b3 7f36 b59f 755c  .....W>.t..6..u\
00000090: cd6c c633 6388 b3b3 b5a1 53a6 caec 7d6a  .l.3c.....S...}j
000000a0: 59a4 9622 2aa2 51ac 8f29 4b0a 0111 b124  Y.."*.Q..)K....$
000000b0: a8da aa4b 0e08 48c0 ba5c 7d33 2733 fa0f  ...K..H..\}3'3..
000000c0: 35b3 47b8 9fcc c22f 7a0c 337f fe37 735f  5.G..../z.3..7s_
000000d0: 165e f937 6edd ab2e 0f68 9980 99bc 0067  .^.7n....h.....g
000000e0: d046 3ea1 2792 96c0 459b 9428 aa25 2700  .F>.'...E..(.%'.
000000f0: 545a 0ed4 a20b cd82 0da5 49d3 061a df68  TZ........I....h
00000100: 481e 33c4 10ef a777 b096 2eba 0d7d 0013  H.3....w.....}..
00000110: b215 5dae 2d5b c2d8 24d8 2c51 0b61 7536  ..].-[..$.,Q.au6
00000120: a9c4 9010 2212 3a2c d828 47b4 5913 5569  ....".:,.(G.Y.Ui
00000130: 2e54 e0e2 df60 d6ba 40ef 425d f8e0 753c  .T...`..@.B]..u<
00000140: 32a9 671b 7d13 f011 0281 2b3e 050c b669  2.g.}.....+>...i
00000150: 6e96 6db2 31a5 c2a0 2516 ae25 8148 742e  n.m.1...%..%.Ht.
00000160: 0854 b524 0cf5 af89 ee5f ee3f 0100 00ff  .T.$....._.?....
00000170: ff03 00f5 6758 03c4 0200 00              ....gX.....
```

We are expecting the content to be a valid JSON object, but it's not. Still, don't panic, we got you covered.

Each URI request will have their own request header file for metadata reference with this format:

```shell
.cache/{sha256}.meta
```

so you can view the metadata of the request like this:

```shell
cat .cache/1b8c2ef6c820e0c0.meta
```

We can easily find out that the response was transferred with `content-encoding:gzip`, this means, and also indicated by the file header `1f8b`, the response body was compressed with gzip.

We can use `gzip` to decompress the file and get the actual content:

```shell
gunzip -c .cache/1b8c2ef6c820e0c0 > .cache/1b8c2ef6c820e0c0.raw
```

Afterwards, we can use `jq` to parse the content as a JSON object:

```shell
$ jq . .cache/1b8c2ef6c820e0c0.raw
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
  "config": {
    "mediaType": "application/vnd.docker.container.image.v1+json",
    "digest": "sha256:31df23ea7daa448f9ccdbbcecce6c14689c8552222b80defd3830707c0139d4f",
    "size": 420
  },
  "layers": [
    {
      "mediaType": "application/vnd.ollama.image.model",
      "digest": "sha256:970aa74c0a90ef7482477cf803618e776e173c007bf957f635f1015bfcfef0e6",
      "size": 274290656
    },
    {
      "mediaType": "application/vnd.ollama.image.license",
      "digest": "sha256:c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4",
      "size": 11357
    },
    {
      "mediaType": "application/vnd.ollama.image.params",
      "digest": "sha256:ce4a164fc04605703b485251fe9f1a181688ba0eb6badb80cc6335c0de17ca0d",
      "size": 17
    }
  ]
}
```






