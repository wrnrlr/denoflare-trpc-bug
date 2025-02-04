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
