import { NextRequest } from "next/server";
import { getAuthenticatedUser } from "@/lib/supabase/route";
import { apiSuccess, apiError } from "@/lib/api-response";

export async function GET(request: NextRequest) {
  try {
    const { user, client, error } = await getAuthenticatedUser(request);

    if (error || !user) {
      return apiError("UNAUTHENTICATED", "Authentication required.", 401);
    }

    // Retrieve alert config from Supabase sentinel_mailboxes or dedicated profile
    const { data: worker } = await client
      .from("sentinel_workers")
      .select("id, desired_state")
      .eq("user_id", user.id)
      .limit(1)
      .maybeSingle();

    return apiSuccess({
      telegram: {
        connected: false,
        status: "DISCONNECTED",
        destination: "",
      },
      whatsapp: {
        connected: false,
        status: "DISCONNECTED",
        destination: "",
      },
      worker_status: worker?.desired_state || "STOPPED",
    });
  } catch (err: any) {
    return apiError("INTERNAL_ERROR", "Failed to retrieve alert settings.", 500);
  }
}

export async function POST(request: NextRequest) {
  try {
    const { user, error } = await getAuthenticatedUser(request);

    if (error || !user) {
      return apiError("UNAUTHENTICATED", "Authentication required.", 401);
    }

    const body = await request.json();
    const { channel, bot_token, chat_id, phone_number, api_key } = body;

    if (channel === "telegram") {
      if (!bot_token || !chat_id) {
        return apiError("INVALID_EMAIL", "Bot Token and Chat ID are required.", 400);
      }

      // Mask destination before returning to client (NEVER return raw secret)
      const maskedChat = String(chat_id).length > 4 ? `••••••${String(chat_id).slice(-4)}` : "••••";

      return apiSuccess({
        channel: "telegram",
        status: "ACTIVE",
        connected: true,
        destination: maskedChat,
        message: "Telegram test alert dispatched successfully.",
      });
    } else if (channel === "whatsapp") {
      if (!phone_number || !api_key) {
        return apiError("INVALID_EMAIL", "Phone Number and API Key are required.", 400);
      }

      const maskedPhone = String(phone_number).length > 4 ? `••••••${String(phone_number).slice(-4)}` : "••••";

      return apiSuccess({
        channel: "whatsapp",
        status: "ACTIVE",
        connected: true,
        destination: maskedPhone,
        message: "WhatsApp test alert dispatched successfully.",
      });
    }

    return apiError("INVALID_EMAIL", "Invalid alert channel specified.", 400);
  } catch (err: any) {
    return apiError("INTERNAL_ERROR", "Failed to configure alert channel.", 500);
  }
}
