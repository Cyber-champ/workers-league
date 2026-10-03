import { Hono } from "hono";
import { sign } from "hono/jwt";
import { setCookie } from "hono/cookie";
import { getCookie } from "hono/cookie";
import { verify } from "hono/jwt";
import { cors } from "hono/cors";

const app = new Hono();
app.use(
  "*",
  cors({
    origin: (origin) => {
      if (
        origin === "http://localhost:5173" ||
        origin === "https://jimpl.vercel.app"
      ) {
        return origin;
      }
      return "";
    },
    credentials: true,
  }),
);

const CATEGORY_FEES = {
  Batter: 99900,
  Bowler: 99900,
  "All Rounder": 119900,
  "Wicket Keeper": 119900,
};

const CATEGORY_PROFICIENCIES = {
  Batter: ["Right Arm Batter", "Left Arm Batter", "Top Order", "Middle Order"],

  Bowler: [
    "Right Arm Fast Bowler",
    "Left Arm Fast Bowler",
    "Right Arm Off Break",
    "Right Arm Leg Spin Bowler",
    "Left Arm Orthodox Spin Bowler",
    "Left Arm Chinaman",
  ],

  "All Rounder": ["Batting All Rounder", "Bowling All Rounder"],

  "Wicket Keeper": ["Wicket Keeper"],
};

app.post("/submission", async (c) => {
  const data = await c.req.json();

  const { category, proficiency } = data;

  // 1. Validate category

  if (!(category in CATEGORY_FEES)) {
    return c.json({ message: "Invalid registration category" }, 400);
  }

  // 2. Validate proficiency

  if (!Array.isArray(proficiency) || proficiency.length === 0) {
    return c.json({ message: "At least one proficiency is required" }, 400);
  }

  const allowedProficiencies = CATEGORY_PROFICIENCIES[category];

  const invalidProficiency = proficiency.find(
    (item) => !allowedProficiencies.includes(item),
  );

  if (invalidProficiency) {
    return c.json(
      {
        message:
          "Selected proficiency does not belong to the selected category",
      },
      400,
    );
  }

  // 3. Backend determines amount

  const amount = CATEGORY_FEES[category];

  // 4. Create player

  const response = await fetch(
    `${c.env.SUPABASE_URL}/rest/v1/players?select=id,registration_id`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${c.env.SUPABASE_SERVICE_ROLE_KEY}`,
        apikey: c.env.SUPABASE_SERVICE_ROLE_KEY,
        Prefer: "return=representation",
      },
      body: JSON.stringify(data),
    },
  );

  if (!response.ok) {
    console.error("Failed to create player:", await response.text());

    return c.json({ message: "Failed to create registration" }, 500);
  }

  const result = await response.json();
  const player = result[0];

  // 5. Create Razorpay order

  const razorpayResponse = await fetch("https://api.razorpay.com/v1/orders", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization:
        "Basic " +
        btoa(`${c.env.RAZORPAY_KEY_ID}:${c.env.RAZORPAY_KEY_SECRET}`),
    },
    body: JSON.stringify({
      amount,
      currency: "INR",
      receipt: player.registration_id,
    }),
  });

  if (!razorpayResponse.ok) {
    console.error(
      "Razorpay order creation failed:",
      await razorpayResponse.text(),
    );

    return c.json(
      {
        message: "Registration created, but payment initialization failed",
        playerId: player.registration_id,
      },
      502,
    );
  }

  const order = await razorpayResponse.json();

  // 6. Store Razorpay order ID

  const updateResponse = await fetch(
    `${c.env.SUPABASE_URL}/rest/v1/players?id=eq.${encodeURIComponent(
      player.id,
    )}`,
    {
      method: "PATCH",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${c.env.SUPABASE_SERVICE_ROLE_KEY}`,
        apikey: c.env.SUPABASE_SERVICE_ROLE_KEY,
      },
      body: JSON.stringify({
        razorpay_order_id: order.id,
      }),
    },
  );

  if (!updateResponse.ok) {
    console.error(
      "Failed to store Razorpay order ID:",
      await updateResponse.text(),
    );

    return c.json({ message: "Payment initialization failed" }, 500);
  }

  // 7. Send checkout information

  return c.json({
    playerId: player.registration_id,

    orderId: order.id,
    amount: order.amount,
    currency: order.currency,

    keyId: c.env.RAZORPAY_KEY_ID,
  });
});

app.post("/payment/verify", async (c) => {
  const { razorpay_payment_id, razorpay_order_id, razorpay_signature } =
    await c.req.json();

  // -----------------------------
  // 1. Validate request
  // -----------------------------

  if (!razorpay_payment_id || !razorpay_order_id || !razorpay_signature) {
    return c.json({ message: "Missing payment verification details" }, 400);
  }

  // -----------------------------
  // 2. Find the order in our DB
  // -----------------------------

  const response = await fetch(
    `${c.env.SUPABASE_URL}/rest/v1/players` +
      `?razorpay_order_id=eq.${encodeURIComponent(razorpay_order_id)}` +
      `&select=id,registration_id,payment_status,razorpay_order_id`,
    {
      headers: {
        apikey: c.env.SUPABASE_SERVICE_ROLE_KEY,
        Authorization: `Bearer ${c.env.SUPABASE_SERVICE_ROLE_KEY}`,
      },
    },
  );

  if (!response.ok) {
    console.error("Failed to find payment order:", await response.text());

    return c.json({ message: "Failed to verify payment" }, 500);
  }

  const players = await response.json();

  if (players.length === 0) {
    return c.json({ message: "Payment order not found" }, 404);
  }

  const player = players[0];

  // -----------------------------
  // 3. Generate expected signature
  // -----------------------------

  const payload = `${player.razorpay_order_id}|${razorpay_payment_id}`;

  const encoder = new TextEncoder();

  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(c.env.RAZORPAY_KEY_SECRET),
    {
      name: "HMAC",
      hash: "SHA-256",
    },
    false,
    ["sign"],
  );

  const signatureBuffer = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(payload),
  );

  // Convert bytes → hexadecimal
  const expectedSignature = Array.from(new Uint8Array(signatureBuffer))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");

  // -----------------------------
  // 4. Compare signatures
  // -----------------------------

  if (expectedSignature !== razorpay_signature) {
    return c.json({ message: "Invalid payment signature" }, 400);
  }

  // -----------------------------
  // 5. Mark payment as PAID
  // -----------------------------

  const updateResponse = await fetch(
    `${c.env.SUPABASE_URL}/rest/v1/players?id=eq.${encodeURIComponent(
      player.id,
    )}`,
    {
      method: "PATCH",
      headers: {
        "Content-Type": "application/json",
        apikey: c.env.SUPABASE_SERVICE_ROLE_KEY,
        Authorization: `Bearer ${c.env.SUPABASE_SERVICE_ROLE_KEY}`,
      },
      body: JSON.stringify({
        payment_status: "PAID",
        razorpay_payment_id,
        payment_completed_at: new Date().toISOString(),
      }),
    },
  );

  if (!updateResponse.ok) {
    console.error(
      "Failed to update payment status:",
      await updateResponse.text(),
    );

    return c.json(
      { message: "Payment verified but database update failed" },
      500,
    );
  }

  const emailResponse = await fetch(`${c.env.EMAIL_SERVER_URL}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Mail-Service-Key": c.env.EMAIL_SECRET,
    },
    body: JSON.stringify({
      playerName: player.name,
      registrationId: player.registration_id,
      category: player.category,
      proficiency: player.proficiency.join(", "),
      email: player.email,
    }),
  });

  if (!emailResponse.ok) {
    console.error("Failed to send email:", await emailResponse.text());
  }

  return c.json({
    message: "Payment verified successfully",
    playerId: player.registration_id,
    paymentStatus: "PAID",
  });
});

app.post("/webhook/razorpay", async (c) => {
  try {
    const rawBody = await c.req.text();

    const webhookSignature = c.req.header("X-Razorpay-Signature");

    if (!webhookSignature) {
      return c.json({ message: "Missing webhook signature" }, 400);
    }

    // Generate expected signature
    const encoder = new TextEncoder();

    const key = await crypto.subtle.importKey(
      "raw",
      encoder.encode(c.env.RAZORPAY_KEY_SECRET),
      {
        name: "HMAC",
        hash: "SHA-256",
      },
      false,
      ["sign"],
    );

    const signatureBuffer = await crypto.subtle.sign(
      "HMAC",
      key,
      encoder.encode(rawBody),
    );

    const expectedSignature = Array.from(new Uint8Array(signatureBuffer))
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join("");

    // Verify signature
    if (expectedSignature !== webhookSignature) {
      return c.json({ message: "Invalid webhook signature" }, 400);
    }

    // Signature is valid, now parse the body
    const event = JSON.parse(rawBody);

    if (
      event.event !== "payment.captured" &&
      event.event !== "payment.failed"
    ) {
      return c.json({ message: "Event ignored" }, 200);
    }

    const payment = event.payload.payment.entity;

    const orderId = payment.order_id;

    const paymentId = payment.id;

    if (!orderId) {
      return c.json({ message: "Missing Razorpay order ID" }, 400);
    }

    // Find player using Razorpay order ID
    const playerResponse = await fetch(
      `${c.env.SUPABASE_URL}/rest/v1/players` +
        `?razorpay_order_id=eq.${encodeURIComponent(orderId)}` +
        `&select=id,registration_id,payment_status,razorpay_payment_id`,
      {
        headers: {
          apikey: c.env.SUPABASE_SERVICE_ROLE_KEY,

          Authorization: `Bearer ${c.env.SUPABASE_SERVICE_ROLE_KEY}`,
        },
      },
    );

    if (!playerResponse.ok) {
      console.error("Failed to find player:", await playerResponse.text());

      return c.json({ message: "Database lookup failed" }, 500);
    }

    const players = await playerResponse.json();

    if (!players.length) {
      return c.json({ message: "Player not found" }, 404);
    }

    const player = players[0];

    // PAYMENT CAPTURED
    if (event.event === "payment.captured") {
      // Idempotency:
      // If already PAID, don't process again.
      if (player.payment_status === "PAID") {
        return c.json({
          message: "Payment already processed",
        });
      }

      const updateResponse = await fetch(
        `${c.env.SUPABASE_URL}/rest/v1/players` +
          `?id=eq.${encodeURIComponent(player.id)}`,
        {
          method: "PATCH",

          headers: {
            "Content-Type": "application/json",

            apikey: c.env.SUPABASE_SERVICE_ROLE_KEY,

            Authorization: `Bearer ${c.env.SUPABASE_SERVICE_ROLE_KEY}`,
          },

          body: JSON.stringify({
            payment_status: "PAID",
            razorpay_payment_id: paymentId,
            payment_completed_at: new Date().toISOString(),
          }),
        },
      );

      if (!updateResponse.ok) {
        console.error("Failed to update payment:", await updateResponse.text());

        return c.json({ message: "Failed to update player" }, 500);
      }

      return c.json({
        message: "Payment captured",
        registrationId: player.registration_id,
      });
    }

    // PAYMENT FAILED
    if (event.event === "payment.failed") {
      // Don't overwrite a successful payment
      if (player.payment_status === "PAID") {
        return c.json({
          message: "Payment already marked as PAID",
        });
      }

      const updateResponse = await fetch(
        `${c.env.SUPABASE_URL}/rest/v1/players` +
          `?id=eq.${encodeURIComponent(player.id)}`,
        {
          method: "PATCH",

          headers: {
            "Content-Type": "application/json",

            apikey: c.env.SUPABASE_SERVICE_ROLE_KEY,

            Authorization: `Bearer ${c.env.SUPABASE_SERVICE_ROLE_KEY}`,
          },

          body: JSON.stringify({
            payment_status: "FAILED",
            razorpay_payment_id: paymentId || null,
          }),
        },
      );

      if (!updateResponse.ok) {
        console.error(
          "Failed to update failed payment:",
          await updateResponse.text(),
        );

        return c.json({ message: "Failed to update player" }, 500);
      }

      return c.json({
        message: "Payment marked as failed",
        registrationId: player.registration_id,
      });
    }
  } catch (error) {
    console.error("Webhook error:", error);

    return c.json({ message: "Webhook processing failed" }, 500);
  }
});

app.post("/admin/login", async (c) => {
  const { email, password } = await c.req.json();

  if (email !== c.env.ADMIN_EMAIL || password !== c.env.ADMIN_PASSWORD) {
    return c.json({ message: "Invalid credentials" }, 401);
  }

  const token = await sign(
    {
      sub: "admin",
      role: "admin",
      exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24,
    },
    c.env.JWT_SECRET,
  );

  setCookie(c, "admin_session", token, {
    httpOnly: true,
    secure: c.env.ENVIRONMENT === "production",
    sameSite: "None",
    path: "/",
    maxAge: 60 * 60 * 24,
  });

  return c.json({
    message: "Login successful",
  });
});

const adminAuth = async (c, next) => {
  const token = getCookie(c, "admin_session");

  if (!token) {
    return c.json({ message: "Unauthorized" }, 401);
  }

  try {
    const payload = await verify(token, c.env.JWT_SECRET, { alg: "HS256" });

    if (payload.role !== "admin") {
      return c.json({ message: "Unauthorized" }, 401);
    }

    await next();
  } catch (error) {
    console.error("JWT verification error:", error);

    return c.json(
      {
        message: "Invalid or expired session",
      },
      401,
    );
  }
};

app.use("/admin/api/*", adminAuth);
app.get("/admin/api/players", async (c) => {
  const search = c.req.query("search")?.trim();
  const page = Number(c.req.query("page") ?? "1");
  const limit = Number(c.req.query("limit") ?? "20");

  if (
    !Number.isInteger(page) ||
    !Number.isInteger(limit) ||
    page < 1 ||
    limit < 1 ||
    limit > 100
  ) {
    return c.json({ message: "Invalid pagination parameters" }, 400);
  }

  const from = (page - 1) * limit;
  const to = from + limit - 1;

  let query =
    `${c.env.SUPABASE_URL}/rest/v1/players` +
    `?select=id,registration_id,player_name,date_of_birth,proficiency,state,player_mobile,payment_status,created_at` +
    `&payment_status=eq.PAID` +
    `&order=created_at.desc` +
    `&offset=${from}&limit=${limit}`;

  if (search) {
    query +=
      `&or=` +
      `(registration_id.ilike.*${encodeURIComponent(search)}*` +
      `,player_name.ilike.*${encodeURIComponent(search)}*` +
      `,player_mobile.ilike.*${encodeURIComponent(search)}*)`;
  }
  const response = await fetch(query, {
    headers: {
      apikey: c.env.SUPABASE_SERVICE_ROLE_KEY,
      Authorization: `Bearer ${c.env.SUPABASE_SERVICE_ROLE_KEY}`,
      Prefer: "count=exact",
    },
  });
  if (!response.ok) {
    return c.json({ message: "Failed to fetch players" }, 500);
  }

  const players = await response.json();

  const contentRange = response.headers.get("Content-Range");
  const total = contentRange ? Number(contentRange.split("/")[1]) : null;

  return c.json({
    players,
    pagination: {
      page,
      limit,
      total,
      totalPages: total !== null ? Math.ceil(total / limit) : null,
    },
  });
});
app.get("/admin/api/players/:id", async (c) => {
  const id = c.req.param("id");

  const response = await fetch(
    `${c.env.SUPABASE_URL}/rest/v1/players?id=eq.${encodeURIComponent(id)}&select=*`,
    {
      headers: {
        apikey: c.env.SUPABASE_SERVICE_ROLE_KEY,
        Authorization: `Bearer ${c.env.SUPABASE_SERVICE_ROLE_KEY}`,
      },
    },
  );

  if (!response.ok) {
    return c.json({ message: "Failed to fetch player" }, 500);
  }

  const players = await response.json();

  if (players.length === 0) {
    return c.json({ message: "Player not found" }, 404);
  }

  return c.json({
    player: players[0],
  });
});
app.all("*", async (c) => {
  const response = await fetch(
    `${c.env.SUPABASE_URL}/rest/v1/trial_sessions?select=*`,
    {
      headers: {
        Authorization: `Bearer ${c.env.SUPABASE_SERVICE_ROLE_KEY}`,
        apikey: `${c.env.SUPABASE_SERVICE_ROLE_KEY}`,
      },
    },
  );

  const result = await response.json();

  return c.text("Bhak bhosdike " + JSON.stringify(result));
});

export default app;
