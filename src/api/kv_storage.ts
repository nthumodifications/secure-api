import { zValidator } from "@hono/zod-validator";
import { Hono } from "hono";
import { z } from "zod";
import { requireAuth } from '../middleware/requireAuth';
import { adminFirestore } from '../config/firebase_admin';

const app = new Hono()
  .get("/:key",
    zValidator(
      'param',
      z.object({
        key: z.string()
      })
    ),
    requireAuth(['kv']),
    async (c) => {
      const validKeys = ["course_color_map", "timetable_display_preferences", "timetable_theme", "user_defined_colors"];
      const { key } = c.req.valid('param')
      if (!validKeys.includes(key)) {
        return c.json({ error: "Invalid key" }, 400);
      }
      // Fetch data from Firestore
      const data = await adminFirestore.collection('users').doc(c.var.user.userid).collection('storage').doc(key).get();
      if (!data.exists) {
        return c.json({ error: "Not found" }, 404);
      }
      return c.json(data.data());
    }
  )
  .post("/:key",
    zValidator(
      'param',
      z.object({
        key: z.string()
      })
    ),
    zValidator(
      'json',
      z.object({
        value: z.any()
      })
    ),
    requireAuth(['kv']),
    async (c) => {
      const validKeys = ["course_color_map", "timetable_display_preferences", "timetable_theme", "user_defined_colors"];
      const { key } = c.req.valid('param')
      const { value } = c.req.valid('json')
      if (!validKeys.includes(key)) {
        return c.json({ error: "Invalid key" }, 400);
      }
      // Update data in Firestore
      await adminFirestore.collection('users').doc(c.var.user.userid).collection('storage').doc(key).set({ value });
      return c.json({ success: true });
    }
  )

export default app;