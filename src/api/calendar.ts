import { zValidator } from "@hono/zod-validator";
import { Hono } from "hono";
import { z } from "zod";
import { requireAuth } from "../middleware/requireAuth";
import { adminFirestore } from "../config/firebase_admin";
import { Timestamp } from "firebase-admin/firestore";
import { lastOfArray } from 'rxdb/plugins/core';

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
                .where("serverTimestamp", ">", new Date(updatedAt))
                .orderBy("serverTimestamp")
                .orderBy("id")
                .limit(limit ?? 10)
                .get();
            const newCheckpoint = data.empty ? 
                { id, updatedAt } : 
                { id: lastOfArray(data.docs)!.id, updatedAt: (lastOfArray(data.docs)!.data()['serverTimestamp'] as Timestamp).toMillis() };
            return c.json({
                events: data.docs.map((doc) => ({ ...doc.data() as { serverTimestamp: Timestamp }, id: doc.id })).map(({ serverTimestamp, ...doc}) => ({ ...doc, updatedAt: serverTimestamp.toMillis() })),
                checkpoint: newCheckpoint,
            });
        })
    .post("/push",
        zValidator(
            "json",
            z.array(z.object({
                newDocumentState: z.object({
                    id: z.string(),
                    updatedAt: z.coerce.number(),
                }),
                assumedMasterState: z.object({
                    id: z.string(),
                    updatedAt: z.coerce.number()
                }).optional(),
            })),
        ),
        requireAuth(["calendar"]),
        async (c) => {
            const changeRows = c.req.valid("json");
            const conflicts = [];
            const user = c.var.user;
            const eventsCol = adminFirestore.collection("users").doc(user.userid).collection("events");
            const batch = adminFirestore.batch();
            const event: {
                id: string;
                documents: { id: string; updatedAt: number; }[];
                checkpoint: { id: string; updatedAt: number; } | null;
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
                        (realMasterState.data()!['serverTimestamp'] as Timestamp).toMillis() !== changeRow.assumedMasterState!.updatedAt
                    )
                ) {
                    const { serverTimestamp, ...doc } = realMasterState.data() as any;
                    conflicts.push({ ...doc, id: realMasterState.id, updatedAt: serverTimestamp.toDate() });
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
                // await batch.commit();
            }
            return c.json(conflicts);
        });

export default app;