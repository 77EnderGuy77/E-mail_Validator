import fs from "fs"
import path from "path";
import { promises as dns } from "dns"
import { EmailCheckResult } from "./interfaces";
// @ts-ignore
import SMTPConnection from "smtp-connection";

/**
 * 
 * @param email string - The email to check
 * @returns true if the email pass the check if it look like this 'example@test.com'
 */
export const syntaxCheck = (email: string): boolean => {
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    return emailRegex.test(email);
}

export const loadList = (filePath: string): Set<string> => {
    const fullPath = path.resolve(process.cwd(), "src/utils", filePath);

    try {
        const content = fs.readFileSync(fullPath, "utf-8");
        return new Set(
            content
                .split(/\r?\n/)
                .map((line: string) => line.trim().toLowerCase())
                .filter((line: string) => line.length > 0 && !line.startsWith("#"))
        );
    } catch (error) {
        console.error(error);
        process.exit(1)
    }
}

/**
 * Checks whether an email's domain is contained in a given set.
 *
 * @param domain - The domain to check
 * @param list - A Set of domains (allowlist, blocklist/disposable)
 * @returns true if the domain is in the list, false otherwise
 */
export const isDomainInList = (domain: string, list: Set<string>): boolean => {
    return domain ? list.has(domain) : false;
};

/**
 * Checks if there is MX 
 * 
 * @param domain - The domain to check
 * @returns true if domain has MX records
 */
export const checkMX = async (domain: string): Promise<boolean | Error> => {
    try {
        const mxRecords = await dns.resolveMx(domain);

        if (mxRecords.length === 0) {
            return Error(`No MX records found`)
        }

        return true;
    } catch (error: any) {
        return Error(`DNS lookup failed: ${error.message}`);
    }
};

/**
 * Checks if there is a role in local part of email
 * 
 * @param email - The email to check
 * @returns true if there is a role in local part
 */
export const isRoleEmail = (email: string): boolean => {
    const local = email.split("@")[0].toLocaleString();
    const roles = ["admin", "info", "support", "postmaster", "noreply"]
    return roles.includes(local);
}

/**
 * Try to establish an SMTP connection to the domain's MX server.
 * @param domain - The domain to check
 * @returns true if the server accepts connection, false if blocked, or Error on DNS failure.
 */
export const isSMTP = async (domain: string): Promise<boolean | Error> => {
    let mxRecords;

    try {
        mxRecords = await dns.resolveMx(domain);
    } catch (error: any) {
        return Error(`DNS lookup failed: ${error.message}`);
    }

    if (!mxRecords || mxRecords.length === 0) {
        return Error(`No MX records found for ${domain}`);
    }

    // Pick the lowest-priority MX server
    const mxHost = mxRecords.sort((a, b) => a.priority - b.priority)[0].exchange;

    return new Promise<boolean>((resolve) => {
        const connection = new SMTPConnection({
            host: mxHost,
            port: 25,
            secure: false,
            connectionTimeout: 5000, // fail fast
            greetingTimeout: 5000,
            socketTimeout: 5000,
        });

        connection.on("error", (err: any) => {
            console.error(`❌ SMTP error for ${domain} [${mxHost}]: ${err.message}`);
            resolve(false);
        });

        connection.connect(() => {
            console.log(`✅ SMTP connection succeeded: ${mxHost}`);
            connection.quit();
            resolve(true);
        });
    });
};

/**
 * Calculate a trust score (0–100) from the EmailCheckResult.
 */
export function calculateScore(result: EmailCheckResult): number {
    let score = 0;

    // Syntax
    if (!result.syntaxValid) return 0;
    score += 30;

    // MX
    if (result.mx?.ok) {
        score += 30;
    } else {
        score -= 20;
    }

    // SMTP
    if (result.smtp?.ok) {
        score += 30;
    } else if (result.smtp?.error) {
        score -= 10; // not fatal, but reduces trust
    }

    // Blocklist / Allowlist
    if (result.inBlocklist) {
        score -= 50;
    }
    if (result.inAllowlist) {
        score += 20;
    }

    // Role-based email (generic mailbox like admin@, support@, etc.)
    if (result.isRole) {
        score -= 10;
    }

    // Normalize
    if (score < 0) score = 0;
    if (score > 100) score = 100;

    return score;
}
