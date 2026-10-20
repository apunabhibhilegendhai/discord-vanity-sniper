export function Unavailable({ title, message }: { title: string; message: string }) {
  return (
    <div className="card" style={{ maxWidth: 640, margin: "8vh auto 0" }} role="alert">
      <p className="small muted">SERVICE UNAVAILABLE</p>
      <h1>{title}</h1>
      <p className="lede">{message}</p>
      <p className="muted">
        No health or config data is shown because it could not be verified. Check the host
        environment and Supabase, then reload.
      </p>
    </div>
  );
}
