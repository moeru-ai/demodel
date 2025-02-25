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
