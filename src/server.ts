// server.ts
import dotenv from "dotenv";
dotenv.config(); // Load .env variables

import Fastify from "fastify";
import { checkEmail } from "./utils/checks";
import { calculateScore, loadList } from "./utils/email-validate";
import { EmailCheckResult } from "./utils/interfaces";

interface IQuerystring {
    email: string | string[];
    skipSMTP?: boolean;
}

interface IHeaders {
    "x-rapidapi-key"?: string;
    "x-rapidapi-host"?: string;
}

interface IReplyBody {
    email: string;
    percentage: number;
    info: EmailCheckResult | EmailCheckResult[];
}

interface IReply {
    code: number;
    message: string;
    body: IReplyBody | IReplyBody[] | null;
}

// Load blocklists
const blocklist = loadList("disposable_email_blocklist.conf");
const trustedDomains = loadList("trusted_domains.conf");

const app = Fastify({ logger: true });

// -------------------------
// Middleware: API key check
// -------------------------
let remaining: number | null = 0;

app.addHook("onRequest", async (req) => {
    console.log("➡️ onRequest - Incoming headers:", req.headers);
});

// 🔎 Log querystring and body before validation
app.addHook("preParsing", async (req, reply, payload) => {
    console.log("➡️ preParsing - Query:", req.query);
    console.log("➡️ preParsing - Raw payload (may be a stream):", payload);
    return payload; // must return payload to continue
});

// 🔎 Log after body parsing
app.addHook("preValidation", async (req) => {
    console.log("➡️ preValidation - Body:", req.body);
});

// 🔎 Log after validation, before handler
app.addHook("preHandler", async (req, reply) => {
    console.log("➡️ preHandler - Headers:", req.headers);
    console.log("➡️ preHandler - Remaining rate limit:", req.headers["x-ratelimit-requests-remaining"]);
});

// 🔎 Log right before sending response
app.addHook("onSend", async (req, reply, payload) => {
    console.log("⬅️ onSend - Outgoing headers:", reply.getHeaders());
    console.log("⬅️ onSend - Outgoing payload:", payload);
    return payload; // must return payload
});

// 🔎 Log after response is sent
app.addHook("onResponse", async (req, reply) => {
    console.log("✅ onResponse - Request completed for:", req.raw.url);
});

// 🔎 Capture errors globally
app.setErrorHandler((err, req, reply) => {
    console.error("💥 Error occurred:", err);
    reply.code(500).send({ code: 500, message: "Internal server error" });
});


// -------------------------
// Single email check
// -------------------------
app.get<{ Querystring: IQuerystring, Headers: IHeaders, Reply: IReply }>("/check", async (request, reply) => {
    const { email, skipSMTP = false } = request.query;
    if (!email) return failure(reply, "Missing email parameter", 400);

    try {
        const result = await checkEmail(email.toString(), blocklist, trustedDomains, skipSMTP, remaining ?? 0);
        if (!result.syntaxValid) return failure(reply, "Invalid email syntax", 422);
        if (!result.mx?.ok) return failure(reply, "No MX records found", 422);

        return success(reply, {
            email,
            percentage: calculateScore(result),
            info: result,
        });
    } catch (err: any) {
        return failure(reply, `Internal error: ${err.message}`, 500);
    }
});

// -------------------------
// Bulk email check
// -------------------------
app.post<{ Headers: IHeaders, Reply: IReply }>("/check-bulk", async (request, reply) => {
    try {
        const data = request.body as { skipSMTP?: boolean; emails?: string[] };
        if (!data?.emails || data.emails.length === 0) return failure(reply, "Missing emails array", 400);

        const skipSMTP = data.skipSMTP ?? false;

        const results = await Promise.all(
            data.emails.map(email => checkEmail(email, blocklist, trustedDomains, skipSMTP, remaining ?? 0))
        );

        const response = results.map(result => ({
            percentage: result.syntaxValid && result.mx?.ok ? calculateScore(result) : 0,
            info: !result.syntaxValid ? "Invalid syntax" : !result.mx?.ok ? "No MX records" : result,
        }));

        return success(reply, response, "Bulk email check completed");
    } catch (err: any) {
        return failure(reply, `Internal error: ${err.message}`, 500);
    }
});

app.get('/ping', async (req, reply) => {
    return reply.code(200).send("pong")
})

// -------------------------
// Start server (Railway PORT or default 3000)
// -------------------------
const PORT = parseInt(process.env.PORT || "3000", 10);
app.listen({ port: PORT, host: "0.0.0.0" }, (err, address) => {
    if (err) {
        console.error("Server failed to start:", err);
        process.exit(1);
    }
    console.log(`Server listening at ${address}`);
});

// -------------------------
// Helper functions
// -------------------------
function success(reply: any, body: any, message = "success", code = 200) {
    return reply.code(code).send({ code, message, body });
}

function failure(reply: any, message: string, code = 400, statusCode = 400) {
    return reply.code(statusCode).send({ code, message, body: null });
}
