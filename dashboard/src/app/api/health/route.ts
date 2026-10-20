import { requireAdmin } from "@/lib/auth";
import { buildHealthView } from "@/lib/health";
import { errorResponse, jsonResponse } from "@/lib/http";
import { DASHBOARD_UNIT, getStore } from "@/lib/store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(request: Request): Promise<Response> {
  try {
    await requireAdmin(request);
    const store = getStore();
    const [record, active] = await Promise.all([
      store.getHealth(DASHBOARD_UNIT),
      store.getActiveConfig(),
    ]);
    return jsonResponse({
      unit: DASHBOARD_UNIT,
      health: buildHealthView(record, new Date(), active?.version ?? null),
    });
  } catch (error) {
    return errorResponse(error);
  }
}
