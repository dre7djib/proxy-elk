import net from 'node:net';
import tls from 'node:tls';

export interface SmtpSettings {
  host: string;
  port: number;
  secure: boolean;
  user?: string;
  password?: string;
  from: string;
}

export interface MailMessage {
  to: string | string[];
  subject: string;
  text: string;
}

/**
 * Minimal SMTP client (EHLO, optional STARTTLS, AUTH LOGIN, DATA).
 * Enough for a spike; prefer nodemailer in production.
 */
export async function sendSmtpMail(
  settings: SmtpSettings,
  message: MailMessage
): Promise<void> {
  const recipients = Array.isArray(message.to) ? message.to : [message.to];
  if (recipients.length === 0) {
    throw new Error('smtp_send: at least one recipient is required');
  }

  const socket = await connect(settings);
  try {
    await expect(socket, 220);
    await write(socket, `EHLO kibana-spike\r\n`);
    const ehlo = await readMultiline(socket, 250);

    if (!settings.secure && /\bSTARTTLS\b/i.test(ehlo)) {
      await write(socket, 'STARTTLS\r\n');
      await expect(socket, 220);
      const upgraded = await upgradeTls(socket, settings.host);
      await write(upgraded, `EHLO kibana-spike\r\n`);
      await readMultiline(upgraded, 250);
      await authenticate(upgraded, settings);
      await transmit(upgraded, settings, recipients, message);
      return;
    }

    await authenticate(socket, settings);
    await transmit(socket, settings, recipients, message);
  } finally {
    socket.destroy();
  }
}

function connect(settings: SmtpSettings): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    const onError = (err: Error) => reject(err);
    if (settings.secure) {
      const s = tls.connect(
        { host: settings.host, port: settings.port, servername: settings.host },
        () => {
          s.off('error', onError);
          resolve(s);
        }
      );
      s.once('error', onError);
      return;
    }
    const s = net.connect({ host: settings.host, port: settings.port }, () => {
      s.off('error', onError);
      resolve(s);
    });
    s.once('error', onError);
  });
}

function upgradeTls(socket: net.Socket, servername: string): Promise<tls.TLSSocket> {
  return new Promise((resolve, reject) => {
    const onError = (err: Error) => reject(err);
    const s = tls.connect({ socket, servername }, () => {
      s.off('error', onError);
      resolve(s);
    });
    s.once('error', onError);
  });
}

async function authenticate(socket: net.Socket, settings: SmtpSettings): Promise<void> {
  if (!settings.user || settings.password === undefined) {
    return;
  }
  await write(socket, 'AUTH LOGIN\r\n');
  await expect(socket, 334);
  await write(socket, `${Buffer.from(settings.user).toString('base64')}\r\n`);
  await expect(socket, 334);
  await write(socket, `${Buffer.from(settings.password).toString('base64')}\r\n`);
  await expect(socket, 235);
}

async function transmit(
  socket: net.Socket,
  settings: SmtpSettings,
  recipients: string[],
  message: MailMessage
): Promise<void> {
  await write(socket, `MAIL FROM:<${settings.from}>\r\n`);
  await expect(socket, 250);
  for (const to of recipients) {
    await write(socket, `RCPT TO:<${to}>\r\n`);
    await expect(socket, 250);
  }
  await write(socket, 'DATA\r\n');
  await expect(socket, 354);

  const toHeader = recipients.join(', ');
  const body = [
    `From: ${settings.from}`,
    `To: ${toHeader}`,
    `Subject: ${message.subject}`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    '',
    message.text.replace(/^\./gm, '..'),
    '.',
    '',
  ].join('\r\n');

  await write(socket, body);
  await expect(socket, 250);
  await write(socket, 'QUIT\r\n');
}

function write(socket: net.Socket, data: string): Promise<void> {
  return new Promise((resolve, reject) => {
    socket.write(data, (err) => (err ? reject(err) : resolve()));
  });
}

function expect(socket: net.Socket, code: number): Promise<string> {
  return readMultiline(socket, code);
}

function readMultiline(socket: net.Socket, expectedCode: number): Promise<string> {
  return new Promise((resolve, reject) => {
    let buffer = '';
    const onData = (chunk: Buffer) => {
      buffer += chunk.toString('utf8');
      const lines = buffer.split(/\r?\n/).filter((l) => l.length > 0);
      if (lines.length === 0) {
        return;
      }
      const last = lines[lines.length - 1];
      // SMTP multiline: "250-…" then final "250 …"
      if (/^\d{3}-/.test(last)) {
        return;
      }
      if (!/^\d{3}[\s-]/.test(last)) {
        return;
      }
      socket.off('data', onData);
      socket.off('error', onError);
      const code = Number(last.slice(0, 3));
      if (code !== expectedCode) {
        reject(new Error(`SMTP expected ${expectedCode}, got: ${buffer.trim()}`));
        return;
      }
      resolve(buffer);
    };
    const onError = (err: Error) => {
      socket.off('data', onData);
      reject(err);
    };
    socket.on('data', onData);
    socket.once('error', onError);
  });
}
