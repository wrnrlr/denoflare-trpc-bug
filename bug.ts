import { initTRPC } from '@trpc/server'
import { fetchRequestHandler } from '@trpc/server/adapters/fetch'

const t = initTRPC.create()
const router = t.router
const publicProcedure = t.procedure
const appRouter = router({
  hello: publicProcedure.query(()=>'hi')
})

export default {
  async fetch(request: Request): Promise<Response> {
    return fetchRequestHandler({
      endpoint: '/trpc',
      req: request,
      router: appRouter,
      createContext: ()=>({})
    })
  }
}
