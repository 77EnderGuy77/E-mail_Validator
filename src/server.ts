import Fastify from "fastify";
import { checkEmail, bulkCheck } from "./utils/checks";
import { calculateScore, loadList } from "./utils/email-validate";

interface IQuerystring {
    email: string | string[];
    skipSMTP?: boolean;
}

interface IHeaders {
    "x-rapidapi-key": string;
    "x-rapidapi-host": string;
}

interface IReplyBody {
    email?: string;
    percentage?: number;
    info: any;
}

interface IReply {
    code: number;
    message: string;
    body: IReplyBody | IReplyBody[] | null;
}

const blocklist = loadList("disposable_email_blocklist.conf");
const trustedDomains = loadList("trusted_domains.conf");

const logger: boolean = Boolean(process.env.LOGGER_ON!);
const app = Fastify({ logger });

// ✅ Header-based API key validation
app.addHook("onRequest", async (request, reply) => {
    const apiKey = request.headers["x-rapidapi-key"];
    if (!apiKey || apiKey !== process.env.RAPIDAPI_KEY) {
        return reply.code(401).send({ error: "Unauthorized" });
    }
});

// Single email check
app.get<{ Querystring: IQuerystring, Reply: IReply }>("/check", async (request, reply) => {
    const { email, skipSMTP } = request.query;

    if (!email || Array.isArray(email)) {
        return failure(reply, "Missing or invalid email parameter", 400);
    }

    try {
        const result = await checkEmail(email, blocklist, trustedDomains, skipSMTP ?? false);

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

// Bulk email check
app.post<{ Headers: IHeaders, Reply: IReply }>("/check-bulk", async (request, reply) => {
    try {
        const data = request.body as { skipSMTP?: boolean; emails?: string[] };

        if (!data?.emails || !Array.isArray(data.emails) || data.emails.length === 0) {
            return failure(reply, "Missing or invalid emails array", 400);
        }

        const skipSMTP = data.skipSMTP ?? false;

        const results = await Promise.all(
            data.emails.map((email) => checkEmail(email, blocklist, trustedDomains, skipSMTP))
        );

        const responseBody = results.map((result) => {
            if (!result.syntaxValid) return { percentage: 0, info: "Invalid email syntax" };
            if (!result.mx?.ok) return { percentage: 0, info: "No MX records found" };

            return { percentage: calculateScore(result), info: result };
        });

        return success(reply, responseBody, "Bulk email check completed");
    } catch (err: any) {
        return failure(reply, `Internal error: ${err.message}`, 500);
    }
});

app.listen({ port: 3000 }, (err, address) => {
    if (err) {
        console.error(err);
        process.exit(1);
    }
    console.log(`Server listening at ${address}`);
});

// --------------------- Helpers ---------------------
function success(reply: any, body: IReplyBody | IReplyBody[], message = "success", code = 200) {
    const response: IReply = { code, message, body };
    return reply.code(code).send(response);
}

function failure(reply: any, message: string, code = 400, statusCode = 400) {
    const response: IReply = { code, message, body: null };
    return reply.code(statusCode).send(response);
}
