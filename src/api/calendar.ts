import { zValidator } from "@hono/zod-validator";
import { Hono } from "hono";
import { z } from "zod";
import { requireAuth } from "../middleware/requireAuth";
import { adminFirestore } from "../config/firebase_admin";
import { FieldPath, FieldValue, FirebaseFirestoreError, Query, QueryDocumentSnapshot } from "firebase-admin/firestore";
import { appendToArray, ensureNotFalsy, flatClone, lastOfArray, type ById, type RxReplicationWriteToMasterRow, type WithDeleted } from 'rxdb/plugins/core';
import { deepCompare } from "../utils/deepCompare";
import { isoStringToServerTimestamp, firestoreRowToDocData, serverTimestampToIsoString, getContentByIds, stripServerTimestampField, stripPrimaryKey } from "../utils/firestore_replication/firestore_replication_utils";
import type { RxDocType, FirestoreCheckpointType } from "../utils/firestore_replication/firestore_replication_types";

const app = new Hono()
  .get("/pull",
    zValidator(
      "query",
      z.object({
        id: z.string(),
        serverTimestamp: z.string(),
        batchSize: z.coerce.number().optional(),
      }),
    ),
    requireAuth(["calendar"]),
    async (c) => {
      const { id, serverTimestamp, batchSize = 10 } = c.req.valid("query");
      const user = c.var.user;

      let newerQuery: Query;
      let sameTimeQuery: Query | undefined;
      const pullQuery = adminFirestore.collection("users").doc(user.userid).collection("events");

      const lastPulledCheckpoint = serverTimestamp ? {
        id,
        serverTimestamp
      } : null;

      if (lastPulledCheckpoint) {
        const lastServerTimestamp = isoStringToServerTimestamp(lastPulledCheckpoint.serverTimestamp);
        newerQuery = pullQuery
          .where('serverTimestamp', '>', lastServerTimestamp)
          .orderBy('serverTimestamp', 'asc')
          .limit(batchSize);
        sameTimeQuery = pullQuery
          .where('serverTimestamp', '==', lastServerTimestamp)
          .where(FieldPath.documentId(), '>', id)
          .orderBy(FieldPath.documentId(), 'asc')
          .limit(batchSize)
      } else {
        newerQuery = pullQuery
          .orderBy('serverTimestamp', 'asc')
          .limit(batchSize);
      }

      let useDocs: QueryDocumentSnapshot<RxDocType>[] = [];
      await adminFirestore.runTransaction(async (_tx) => {
        useDocs = [];
        const [
          newerQueryResult,
          sameTimeQueryResult
        ] = await Promise.all([
          newerQuery.get(),
          sameTimeQuery ? sameTimeQuery.get() : undefined
        ]);
        if (sameTimeQuery) {
          useDocs = ensureNotFalsy(sameTimeQueryResult).docs as any;
        }
        const missingAmount = batchSize - useDocs.length;
        if (missingAmount > 0) {
          const additionalDocs = newerQueryResult.docs.slice(0, missingAmount).filter(x => !!x);
          appendToArray(useDocs, additionalDocs);
        }
      });

      if (useDocs.length === 0) {
        return c.json({
          checkpoint: lastPulledCheckpoint ?? null,
          documents: []
        });
      }
      const lastDoc = ensureNotFalsy(lastOfArray(useDocs));
      const documents: WithDeleted<RxDocType>[] = useDocs
        .map(row => firestoreRowToDocData(
          'serverTimestamp',
          'id',
          row
        ));
      const newCheckpoint: FirestoreCheckpointType = {
        id: lastDoc.id,
        serverTimestamp: serverTimestampToIsoString('serverTimestamp', lastDoc.data())
      };
      const ret = {
        documents: documents,
        checkpoint: newCheckpoint
      };
      return c.json(ret);
    })
  .post("/push",
    zValidator(
      "json",
      z.array(z.object({
        newDocumentState: z.object({
          id: z.string().optional(),
          _deleted: z.boolean()
        }),
        assumedMasterState: z.object({
          id: z.string().optional(),
          _deleted: z.boolean()
        }).optional(),
      })),
    ),
    requireAuth(["calendar"]),
    async (c) => {
      const rows = c.req.valid("json") as RxReplicationWriteToMasterRow<RxDocType>[];
      const user = c.var.user;
      const eventsRef = adminFirestore.collection("users").doc(user.userid).collection("events");

      const writeRowsById: ById<RxReplicationWriteToMasterRow<RxDocType>> = {};
      const docIds: string[] = rows
        .map(row => {
          const docId = (row.newDocumentState)['id'];
          if (!docId) return;
          writeRowsById[docId] = row;
          return docId;
        })
        .filter(x => !!x) as string[];
      let conflicts: WithDeleted<RxDocType>[] = [];

      /**
       * Everything must run INSIDE of the transaction
       * because on tx-errors, firebase will re-run the transaction on some cases.
       * @link https://firebase.google.com/docs/firestore/manage-data/transactions#transaction_failure
       * @link https://firebase.google.com/docs/firestore/manage-data/transactions
       */
      await adminFirestore.runTransaction(async (_tx) => {
        conflicts = []; // reset in case the tx has re-run.
        /**
         * @link https://stackoverflow.com/a/48423626/3443137
         */

        const getQuery = (ids: string[]) => {
          return eventsRef
            .where(FieldPath.documentId(), 'in', ids)
            .get()
            .then(result => result.docs)
            .catch(error => {
              if (error?.code && (error as FirebaseFirestoreError).code === 'permission-denied') {
                // Query may fail due to rules using 'resource' with non existing ids
                // So try to get the docs one by one
                return Promise.all(
                  ids.map(id => eventsRef.doc(id).get())
                )
                  .then(docs => docs.filter(doc => doc.exists))
              }
              throw error;
            }) as Promise<QueryDocumentSnapshot<RxDocType>[]>;
        };

        const docsInDbResult = await getContentByIds<RxDocType>(docIds, getQuery);

        const docsInDbById: ById<RxDocType> = {};
        docsInDbResult.forEach(row => {
          const docDataInDb = stripServerTimestampField('serverTimestamp', row.data());
          const docId = row.id;
          (docDataInDb as any)['id'] = docId;
          docsInDbById[docId] = docDataInDb;
        });

        /**
         * @link https://firebase.google.com/docs/firestore/manage-data/transactions#batched-writes
         */
        const batch = adminFirestore.batch();
        let hasWrite = false;
        await Promise.all(
          Object.entries(writeRowsById).map(async ([docId, writeRow]) => {
            const docInDb: RxDocType | undefined = docsInDbById[docId];
            console.log(docInDb, writeRow.assumedMasterState, deepCompare(docInDb, writeRow.assumedMasterState), docInDb &&
            (
              !writeRow.assumedMasterState ||
              (deepCompare(docInDb, writeRow.assumedMasterState) === false)
            ));
            if (
              docInDb &&
              (
                !writeRow.assumedMasterState ||
                (deepCompare(docInDb, writeRow.assumedMasterState) === false)
              )
            ) {
              // Conflict if doc exists and assumedMasterState is different
              console.log('[PUSH] Conflict detected', docId);
              conflicts.push(docInDb as any);
            } else {
              console.log('[PUSH] Write', docId);
              // No conflict if doc does not exist or assumedMasterState is the same
              hasWrite = true;
              const docRef = eventsRef.doc(docId);
              const writeDocData = flatClone(writeRow.newDocumentState);
              (writeDocData as any)['serverTimestamp'] = FieldValue.serverTimestamp();
              if (!docInDb) {
                // insert
                batch.set(docRef, stripPrimaryKey('id', writeDocData));
              } else {
                // update
                batch.update(docRef, stripPrimaryKey('id', writeDocData));
              }
            }
          })
        );

        if (hasWrite) {
          await batch.commit();
        }
      });
      return c.json(conflicts);
    });

export default app;