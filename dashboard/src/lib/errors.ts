/**
 * A datastore failure that is safe to describe to the operator.
 * The message must never contain an upstream response body, file path, or secret.
 */
export class DatastoreError extends Error {
  constructor(message = "The dashboard datastore is unavailable.") {
    super(message);
    this.name = "DatastoreError";
  }
}
