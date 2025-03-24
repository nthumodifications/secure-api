import { zValidator } from "@hono/zod-validator";
import { Hono } from "hono";
import { z } from "zod";
import { requireAuth } from "../middleware/requireAuth";
import { adminFirestore } from "../config/firebase_admin";
import { Timestamp } from "firebase-admin/firestore";

const app = new Hono()
    .get("/pull",
        zValidator(
            "query",
            z.object({
                id: z.string(),
                updatedAt: z.coerce.number(),
                limit: z.coerce.number().optional(),
            }),
        ),
        requireAuth(["calendar"]),
        async (c) => {
            const { id, updatedAt, limit } = c.req.valid("query");
            const user = c.var.user;
            const data = await adminFirestore
                .collection("users")
                .doc(user.userid)
                .collection("events")
                .where("serverTimestamp", ">", updatedAt)
                .limit(limit ?? 10)
                .get();
            console.log('path', `users/${user.userid}/events`);
            console.log(data);
            const newCheckpoint = data.empty ? { id, updatedAt } : { id: data.docs[data.docs.length - 1].id, updatedAt: (data.docs[data.docs.length - 1].data()['serverTimestamp'] as Timestamp).toMillis() };
            return c.json({
                events: data.docs.map((doc) => doc.data()).map(({serverTimestamp, ...doc}) => ({ ...doc, id: doc['id'] })),
                checkpoint: newCheckpoint,
            });
        })
    .post("/push",
        zValidator(
            "json",
            z.array(z.object({
                newDocumentState: z.object({
                    id: z.string(),
                    updatedAt: z.string(),
                }),
                assumedMasterState: z.object({
                    id: z.string(),
                    updatedAt: z.string(),
                }).optional(),
            })),
        ),
        requireAuth(["calendar"]),
        async (c) => {
            // return unimplemented
            return c.json([]);
            const changeRows = c.req.valid("json");
            const conflicts = [];
            const user = c.var.user;
            const eventsCol = adminFirestore.collection("users").doc(user.userid).collection("events");
            const batch = adminFirestore.batch();
            const event: {
                id: string;
                documents: { id: string; updatedAt: string; }[];
                checkpoint: { id: string; updatedAt: string; } | null;
            } = {
                id: user.userid,
                documents: [],
                checkpoint: null
            };
            for (const changeRow of changeRows) {
                const realMasterState = await eventsCol.doc(changeRow.newDocumentState.id).get();
                if (
                    realMasterState.exists && !changeRow.assumedMasterState ||
                    (
                        realMasterState.exists && changeRow.assumedMasterState &&
                        realMasterState.data()!['serverTimestamp'] !== changeRow.assumedMasterState!.updatedAt
                    )
                ) {
                    const { serverTimestamp, ...doc } = realMasterState.data() as any;
                    conflicts.push({ ...doc, id: doc['id'], updatedAt: serverTimestamp.toDate() });
                } else {
                    const { updatedAt, ...newDocumentState } = changeRow.newDocumentState;
                    batch.set(eventsCol.doc(changeRow.newDocumentState.id), {
                        ...newDocumentState,
                        serverTimestamp: Timestamp.fromDate(new Date(changeRow.newDocumentState.updatedAt)),
                    });
                    event.documents.push(changeRow.newDocumentState);
                    event.checkpoint = { id: changeRow.newDocumentState.id, updatedAt: changeRow.newDocumentState.updatedAt };
                }
            }
            if (event.documents.length > 0) {
                await batch.commit();
            }
            return c.json(conflicts);
        });

export default app;