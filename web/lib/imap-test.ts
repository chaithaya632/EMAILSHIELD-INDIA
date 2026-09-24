/**
 * web/lib/imap-test.ts
 * Real IMAP TLS connection tester and message header retriever for Gmail Sentinel mailboxes.
 * 
 * Invariants:
 * 1. Strict SSRF Protection: Rejects any host other than imap.gmail.com:993.
 * 2. TLS Certificate Verification: Mandatory TLS with rejectUnauthorized: true.
 * 3. Step validation: Greeting -> LOGIN -> SELECT INBOX -> (optional FETCH_HEADERS) -> LOGOUT.
 * 4. Zero Credential Exposure: Password is never logged, printed, or echoed in errors.
 */

import tls from "node:tls";

export interface ImapMessageHeader {
  uid: number;
  subject: string;
  sender: string;
  recipient?: string;
  date: string;
  messageId: string;
}

export interface ImapTestOptions {
  fetchMessages?: boolean;
  maxMessages?: number;
}

export interface ImapTestResult {
  success: boolean;
  message: string;
  error?: string;
  step?: "DNS_TLS" | "GREETING" | "LOGIN" | "SELECT_INBOX" | "FETCH_HEADERS" | "LOGOUT";
  messages?: ImapMessageHeader[];
  totalMessages?: number;
}

export function decodeMimeWord(str: string): string {
  if (!str) return "";
  return str.replace(/=\?([^?]+)\?([BQbq])\?([^?]*)\?=/g, (_, charset, encoding, text) => {
    try {
      if (encoding.toUpperCase() === "B") {
        return Buffer.from(text, "base64").toString(
          charset.toLowerCase() === "utf-8" ? "utf-8" : "latin1"
        );
      } else if (encoding.toUpperCase() === "Q") {
        return text
          .replace(/_/g, " ")
          .replace(/=([0-9A-Fa-f]{2})/g, (_: string, hex: string) => {
            return String.fromCharCode(parseInt(hex, 16));
          });
      }
    } catch {
      return text;
    }
    return text;
  });
}

export function parseHeaderBlock(rawHeaders: string): {
  subject: string;
  sender: string;
  recipient: string;
  date: string;
  messageId: string;
} {
  const lines = rawHeaders.split(/\r?\n/);
  const unfolded: string[] = [];
  for (const line of lines) {
    if (/^[ \t]/.test(line) && unfolded.length > 0) {
      unfolded[unfolded.length - 1] += " " + line.trim();
    } else if (line.trim().length > 0) {
      unfolded.push(line);
    }
  }

  let subject = "No Subject";
  let sender = "Unknown Sender";
  let recipient = "";
  let date = "";
  let messageId = "";

  for (const line of unfolded) {
    const colonIdx = line.indexOf(":");
    if (colonIdx === -1) continue;
    const headerName = line.slice(0, colonIdx).trim().toLowerCase();
    const headerVal = decodeMimeWord(line.slice(colonIdx + 1).trim());

    if (headerName === "subject") subject = headerVal || "No Subject";
    else if (headerName === "from") sender = headerVal || "Unknown Sender";
    else if (headerName === "to") recipient = headerVal;
    else if (headerName === "date") date = headerVal;
    else if (headerName === "message-id") messageId = headerVal;
  }

  return { subject, sender, recipient, date, messageId };
}

export function parseImapFetchResponses(rawOutput: string): ImapMessageHeader[] {
  const messages: ImapMessageHeader[] = [];
  const fetchRegex = /\*\s+(\d+)\s+FETCH\s+\(([\s\S]*?)(?=\*\s+\d+\s+FETCH|\r?\nA\d+\s+OK|$)/gi;
  let match: RegExpExecArray | null;

  while ((match = fetchRegex.exec(rawOutput)) !== null) {
    const seq = parseInt(match[1], 10);
    const bodyPart = match[2];
    const uidMatch = bodyPart.match(/\bUID\s+(\d+)\b/i);
    const uid = uidMatch ? parseInt(uidMatch[1], 10) : seq;

    const literalMatch = bodyPart.match(/\{(\d+)\}\r?\n([\s\S]*)/);
    let headerText = "";
    if (literalMatch) {
      headerText = literalMatch[2];
      const lastParen = headerText.lastIndexOf(")");
      if (lastParen !== -1) {
        headerText = headerText.slice(0, lastParen);
      }
    } else {
      headerText = bodyPart;
    }

    const parsed = parseHeaderBlock(headerText);
    messages.push({
      uid,
      subject: parsed.subject,
      sender: parsed.sender,
      recipient: parsed.recipient,
      date: parsed.date || new Date().toISOString(),
      messageId: parsed.messageId || `<uid-${uid}@gmail.local>`,
    });
  }

  messages.sort((a, b) => b.uid - a.uid);
  return messages;
}

export async function testGmailImapConnection(
  email: string,
  appPassword: string,
  options?: ImapTestOptions
): Promise<ImapTestResult> {
  const host = "imap.gmail.com";
  const port = 993;
  const timeoutMs = 15000;

  // SSRF guard
  const cleanEmail = email.trim();
  const cleanPassword = appPassword.trim();

  if (!cleanEmail || !cleanEmail.includes("@")) {
    return {
      success: false,
      message: "Invalid email address format.",
      error: "INVALID_EMAIL",
      step: "DNS_TLS",
    };
  }

  if (!cleanPassword) {
    return {
      success: false,
      message: "App Password cannot be empty.",
      error: "EMPTY_PASSWORD",
      step: "LOGIN",
    };
  }

  return new Promise<ImapTestResult>((resolve) => {
    let resolved = false;
    let socket: tls.TLSSocket | null = null;
    let currentStep: "GREETING" | "LOGIN" | "SELECT_INBOX" | "FETCH_HEADERS" | "LOGOUT" = "GREETING";
    let buffer = "";
    let fetchBuffer = "";
    let totalMessages = 0;
    let parsedMessages: ImapMessageHeader[] = [];

    const finish = (result: ImapTestResult) => {
      if (resolved) return;
      resolved = true;
      if (timer) clearTimeout(timer);
      try {
        if (socket && !socket.destroyed) {
          socket.end();
          socket.destroy();
        }
      } catch {
        // ignore socket cleanup error
      }
      resolve(result);
    };

    const timer = setTimeout(() => {
      finish({
        success: false,
        message: `Connection to ${host}:${port} timed out after ${timeoutMs / 1000}s.`,
        error: "TIMEOUT",
        step: currentStep === "GREETING" ? "DNS_TLS" : currentStep,
      });
    }, timeoutMs);

    try {
      socket = tls.connect(
        {
          host,
          port,
          servername: host,
          minVersion: "TLSv1.2",
          rejectUnauthorized: true,
        },
        () => {
          // Connected with verified TLS certificate
        }
      );

      socket.setEncoding("utf8");

      socket.on("data", (data: string) => {
        if (currentStep === "FETCH_HEADERS") {
          fetchBuffer += data;
          if (fetchBuffer.includes("A003 OK") || fetchBuffer.includes("A003 NO") || fetchBuffer.includes("A003 BAD")) {
            if (fetchBuffer.includes("A003 OK")) {
              parsedMessages = parseImapFetchResponses(fetchBuffer);
            }
            currentStep = "LOGOUT";
            try {
              socket?.write("A004 LOGOUT\r\n");
            } catch {
              // ignore
            }
            finish({
              success: true,
              message: `Successfully connected to imap.gmail.com:993 and retrieved ${parsedMessages.length} message headers.`,
              step: "FETCH_HEADERS",
              messages: parsedMessages,
              totalMessages,
            });
            return;
          }
          return;
        }

        buffer += data;
        const lines = buffer.split("\r\n");
        buffer = lines.pop() || "";

        for (const line of lines) {
          const trimmed = line.trim();

          if (currentStep === "GREETING") {
            if (trimmed.startsWith("* OK")) {
              // Greeting received, send LOGIN command
              currentStep = "LOGIN";
              const safeEmail = cleanEmail.replace(/["\\]/g, "\\$&");
              const safePass = cleanPassword.replace(/["\\]/g, "\\$&");
              socket?.write(`A001 LOGIN "${safeEmail}" "${safePass}"\r\n`);
            } else if (trimmed.startsWith("* BYE") || trimmed.startsWith("* NO")) {
              finish({
                success: false,
                message: "Gmail IMAP rejected initial connection: " + trimmed,
                error: "CONNECTION_REJECTED",
                step: "GREETING",
              });
              return;
            }
          } else if (currentStep === "LOGIN") {
            if (trimmed.startsWith("A001 OK")) {
              // Login successful, verify INBOX access
              currentStep = "SELECT_INBOX";
              socket?.write("A002 SELECT INBOX\r\n");
            } else if (trimmed.startsWith("A001 NO") || trimmed.startsWith("A001 BAD")) {
              finish({
                success: false,
                message: "Gmail authentication failed. Please check your Gmail address and 16-character Google App Password.",
                error: "AUTHENTICATION_FAILED",
                step: "LOGIN",
              });
              return;
            }
          } else if (currentStep === "SELECT_INBOX") {
            const existsMatch = trimmed.match(/^\*\s+(\d+)\s+EXISTS/i);
            if (existsMatch) {
              totalMessages = parseInt(existsMatch[1], 10);
            }

            if (trimmed.startsWith("A002 OK")) {
              // INBOX selected successfully. Check if message headers should be fetched
              if (options?.fetchMessages && totalMessages > 0) {
                currentStep = "FETCH_HEADERS";
                const maxToFetch = Math.min(options?.maxMessages || 50, 100);
                const startSeq = Math.max(1, totalMessages - maxToFetch + 1);
                fetchBuffer = "";
                socket?.write(`A003 FETCH ${startSeq}:${totalMessages} (UID RFC822.SIZE BODY.PEEK[HEADER.FIELDS (SUBJECT FROM TO DATE MESSAGE-ID)])\r\n`);
                return;
              }

              // Normal flow without fetching messages
              currentStep = "LOGOUT";
              try {
                socket?.write("A003 LOGOUT\r\n");
              } catch {
                // ignore
              }
              finish({
                success: true,
                message: "Successfully connected to imap.gmail.com:993 and verified INBOX access.",
                step: "SELECT_INBOX",
                totalMessages,
                messages: [],
              });
              return;
            } else if (trimmed.startsWith("A002 NO") || trimmed.startsWith("A002 BAD")) {
              finish({
                success: false,
                message: "Authenticated successfully, but failed to select INBOX: " + trimmed,
                error: "INBOX_SELECTION_FAILED",
                step: "SELECT_INBOX",
              });
              return;
            }
          }
        }
      });

      socket.on("error", (err: Error) => {
        // Sanitize error message to guarantee no sensitive data is leaked
        const cleanMsg = err.message ? err.message.replace(/[\r\n\t]/g, " ") : "TLS Socket Error";
        finish({
          success: false,
          message: `TLS IMAP connection failed: ${cleanMsg}`,
          error: "SOCKET_ERROR",
          step: currentStep === "GREETING" ? "DNS_TLS" : currentStep,
        });
      });

      socket.on("close", () => {
        if (!resolved) {
          finish({
            success: false,
            message: "Connection closed unexpectedly by Gmail IMAP server.",
            error: "CONNECTION_CLOSED",
            step: currentStep,
          });
        }
      });
    } catch (err: any) {
      finish({
        success: false,
        message: `Failed to initiate TLS connection: ${err?.message || "Unknown error"}`,
        error: "INITIATION_ERROR",
        step: "DNS_TLS",
      });
    }
  });
}
