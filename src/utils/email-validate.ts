import fs from "fs"
import path from "path";
import whois from "whois-json";
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

export async function hasSPF(domain: string): Promise<boolean> {
    try {
        const records = await dns.resolveTxt(domain);
        return records.some(txt => txt.join("").toLowerCase().startsWith("v=spf1"));
    } catch {
        return false;
    }
}


export async function hasDMARC(domain: string): Promise<boolean> {
    try {
        const records = await dns.resolveTxt("_dmarc." + domain);
        return records.some(txt => txt.join("").toLowerCase().startsWith("v=dmarc1"));
    } catch {
        return false;
    }
}

export async function getDomainAge(domain: string): Promise<number> {
    try {
        const info: any = await whois(domain);

        // whois-json may return an array or object
        let creationDate: string | undefined;

        if (Array.isArray(info)) {
            // Pick the first element that has creationDate
            creationDate = info.find((el: any) => el.creationDate)?.creationDate;
        } else {
            creationDate = info.creationDate;
        }

        console.log(creationDate)
        if (creationDate) {
            const created = new Date(creationDate);
            const now = new Date();
            const age = (now.getTime() - created.getTime()) / (1000 * 60 * 60 * 24 * 365);
            return Math.floor(age);
        }
    } catch (err) {
        console.error(`WHOIS lookup failed for ${domain}: ${err}`);
    }

    return 0; // unknown or error
}

/**
 * Calculate a trust score (0–100) from the EmailCheckResult.
 */
export function calculateScore(result: EmailCheckResult): number {
    let score = 0;

    // Syntax check: mandatory
    if (!result.syntaxValid) return 0;
    score += 20;

    // MX records
    if (result.mx?.ok) {
        score += 15;
    }

    // SMTP verification
    if (result.smtp?.ok) {
        score += 20;
    }

    // Blocklist / Trusted domains
    if (result.inBlocklist) {
        score -= 20; // still penalize
    }
    if (result.inTrustedDomains || result.noProbeList) {
        score += 10;
    }

    // Disposable domain
    if (result.isDisposable) {
        score -= 25;
    }

    // Role-based email
    if (result.isRole) {
        score -= 5;
    }

    // SPF / DMARC security checks
    if (result.hasSPF) score += 10;
    if (result.hasDMARC) score += 10;

    // Domain age (more trust for older domains)
    if (result.domainAgeYears && result.domainAgeYears >= 1) {
        score += Math.min(result.domainAgeYears, 10); // max +10 points
    }

    // Normalize between 0 and 100
    if (score < 0) score = 0;
    if (score > 100) score = 100;

    return score;
}

