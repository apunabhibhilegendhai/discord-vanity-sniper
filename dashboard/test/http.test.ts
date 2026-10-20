import assert from "node:assert/strict";
import test from "node:test";
import { DatastoreError } from "../src/lib/errors";
import { errorResponse, HttpError } from "../src/lib/http";

test("datastore failures become a 503 with a safe message", async () => {
  const response = errorResponse(
    new DatastoreError("The dashboard data file is unreadable or corrupt."),
  );
  assert.equal(response.status, 503);
  assert.equal(response.headers.get("cache-control"), "no-store, max-age=0");
  const body = (await response.json()) as { error: string; message: string };
  assert.equal(body.error, "datastore_unavailable");
  assert.equal(body.message, "The dashboard data file is unreadable or corrupt.");
  assert.doesNotMatch(body.message, /[\\/]|upstream|stack/i);
});

test("auth unavailability stays an explicit 503", async () => {
  const response = errorResponse(
    new HttpError(503, "auth_unavailable", "Supabase Auth is unavailable."),
  );
  assert.equal(response.status, 503);
  const body = (await response.json()) as { error: string };
  assert.equal(body.error, "auth_unavailable");
});
