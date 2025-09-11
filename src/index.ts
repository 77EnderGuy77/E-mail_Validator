import Fastify from "fastify";
import { checkEmail } from "./utils/checks";
import { calculateScore, loadList } from "./utils/email-validate";

interface IQuerystring {
    email: string[] | string;
    skipSMTP: boolean;
}

interface IHeaders {
    "x-rapidapi-key": string;
    "x-rapidapi-host": string;
}

interface IReplyBody {
    email: string;
    percentage: number;
    info: any;
}

interface IReply {
    code: number;
    message: string;
    body: IReplyBody | null;
}

const blocklist = loadList("disposable_email_blocklist.conf");
const trustedDomains = loadList("trusted_domains.conf");

const app = Fastify({ logger: true });

// Header check
app.addHook("onRequest", async (request, reply) => {
    const apiKey = request.headers["x-rapidapi-key"];
    if (!apiKey || apiKey !== process.env.RAPIDAPI_KEY) {
        return reply.code(401).send({ code: 401, message: "Unauthorized", body: null });
    }
});

// Single email check
app.get<{ Querystring: IQuerystring, Reply: IReply }>("/check", async (request, reply) => {
    const { email, skipSMTP } = request.query as { email: string, skipSMTP: boolean };

    if (!email) return failure(reply, "Missing email parameter", 400);

    try {
        const result = await checkEmail(email, blocklist, trustedDomains, skipSMTP);

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
        if (!data?.emails || data.emails.length === 0) return failure(reply, "Missing emails array", 400);

        const skipSMTP = data.skipSMTP ?? false;

        const results = await Promise.all(
            data.emails.map(email => checkEmail(email, blocklist, trustedDomains, skipSMTP))
        );

        const response = results.map(result => ({
            percentage: result.syntaxValid && result.mx?.ok ? calculateScore(result) : 0,
            info: !result.syntaxValid ? "Invalid syntax" : !result.mx?.ok ? "No MX records" : result,
        }));

        return success(reply, response as any, "Bulk email check completed");
    } catch (err: any) {
        return failure(reply, `Internal error: ${err.message}`, 500);
    }
});

export default async function handler(req: any, res: any) {
    await app.ready();
    app.server.emit("request", req, res);
}

// Helpers
function success(reply: any, body: any, message = "success", code = 200) {
    return reply.code(code).send({ code, message, body });
}

function failure(reply: any, message: string, code = 400, statusCode = 400) {
    return reply.code(statusCode).send({ code, message, body: null });
}
