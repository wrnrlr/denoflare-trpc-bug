import { initTRPC } from '@trpc/server'
import { fetchRequestHandler } from '@trpc/server/adapters/fetch'

// Just uncommenting this line will also break denoflare with the same issue
// const t = initTRPC.create()

export default {
  async fetch(request: Request): Promise<Response> {
    return new Response('Hi')
  }
}
