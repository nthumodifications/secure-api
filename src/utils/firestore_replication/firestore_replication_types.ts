import type { QueryDocumentSnapshot } from "@google-cloud/firestore";

export type FirestoreCheckpointType = {
  id: string;
  serverTimestamp: string;
};
export type RxDocType = {
  id: string | undefined;
};

export type GetQuery<RxDocType> = (ids: string[]) => Promise<QueryDocumentSnapshot<RxDocType>[]>;
