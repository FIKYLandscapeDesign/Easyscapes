import crypto from "node:crypto";

function verifyStripeSignature(payload, signatureHeader, secret) {
  if (!signatureHeader || !secret) return false;

  const parts = signatureHeader.split(",");
  const timestamp = parts
    .find((part) => part.startsWith("t="))
    ?.split("=")[1];

  const signatures = parts
    .filter((part) => part.startsWith("v1="))
    .map((part) => part.split("=")[1]);

  if (!timestamp || signatures.length === 0) return false;

  // Reject old webhook requests.
  const age = Math.abs(Math.floor(Date.now() / 1000) - Number(timestamp));
  if (age > 300) return false;

  const signedPayload = `${timestamp}.${payload}`;

  const expectedSignature = crypto
    .createHmac("sha256", secret)
    .update(signedPayload, "utf8")
    .digest("hex");

  return signatures.some((signature) => {
    try {
      return crypto.timingSafeEqual(
        Buffer.from(expectedSignature, "hex"),
        Buffer.from(signature, "hex")
      );
    } catch {
      return false;
    }
  });
}

export default async (req) => {
  if (req.method !== "POST") {
    return new Response("Method not allowed", { status: 405 });
  }

  const stripeWebhookSecret = process.env.STRIPE_WEBHOOK_SECRET;
  const brevoApiKey = process.env.BREVO_API_KEY;
  const brevoTemplateId = process.env.BREVO_TEMPLATE_ID;

  if (!stripeWebhookSecret || !brevoApiKey || !brevoTemplateId) {
    console.error("Required environment variables are missing.");
    return new Response("Server configuration error", { status: 500 });
  }

  const rawBody = await req.text();
  const stripeSignature = req.headers.get("stripe-signature");

  if (!verifyStripeSignature(rawBody, stripeSignature, stripeWebhookSecret)) {
    console.error("Invalid Stripe webhook signature.");
    return new Response("Invalid signature", { status: 400 });
  }

  let event;

  try {
    event = JSON.parse(rawBody);
  } catch {
    return new Response("Invalid JSON", { status: 400 });
  }

  // We only act when a Checkout payment has successfully completed.
  if (event.type !== "checkout.session.completed") {
    return new Response("Event ignored", { status: 200 });
  }

  const session = event.data?.object;

  if (!session || session.payment_status !== "paid") {
    return new Response("Payment not complete", { status: 200 });
  }

  const email =
    session.customer_details?.email ||
    session.customer_email;

  const customerName =
    session.customer_details?.name || "";

  if (!email) {
    console.error("Paid Checkout Session has no customer email.");
    return new Response("Customer email missing", { status: 400 });
  }

  const amount = session.amount_total
    ? (session.amount_total / 100).toFixed(2)
    : "";

  const currency = (session.currency || "aud").toUpperCase();

  const brevoResponse = await fetch(
    "https://api.brevo.com/v3/smtp/email",
    {
      method: "POST",
      headers: {
        "accept": "application/json",
        "content-type": "application/json",
        "api-key": brevoApiKey
      },
      body: JSON.stringify({
        to: [
          {
            email,
            name: customerName
          }
        ],
        templateId: Number(brevoTemplateId),
        params: {
          customer_name: customerName,
          order_amount: amount,
          currency: currency,
          stripe_session_id: session.id
        }
      })
    }
  );

  if (!brevoResponse.ok) {
    const errorText = await brevoResponse.text();
    console.error("Brevo error:", errorText);
    return new Response("Email delivery request failed", { status: 500 });
  }

  console.log(`Easyscapes confirmation requested for Stripe session ${session.id}`);

  return new Response("Success", { status: 200 });
};

export const config = {
  path: "/stripe-webhook"
};
