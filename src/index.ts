import { Hono } from 'hono'

const app = new Hono()

app.get('/', (c) => {
  return c.text('Hello NTHUMods Auth Server!')
})

const port = process.env.PORT || 3000;

export default {
  port: port,
  fetch: app.fetch,
}
