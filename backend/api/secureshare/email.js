
const nodemailer = require("nodemailer");

function createEmailService({
  transporter,
  frontendUrl,
  from,
}) {
  if (!transporter || typeof transporter.sendMail !== "function") {
    throw new TypeError("A valid email transporter is required.");
  }

  if (typeof frontendUrl !== "string" || !frontendUrl.trim()) {
    throw new TypeError("A valid frontend URL is required.");
  }

  if (typeof from !== "string" || !from.trim()) {
    throw new TypeError("A valid sender address is required.");
  }

  return {
    async sendVerificationEmail({ to, token }) {
      if (
        typeof to !== "string" ||
        typeof token !== "string" ||
        !/^[a-f0-9]{64}$/i.test(token)
      ) {
        throw new TypeError("Invalid verification email details.");
      }

      const verificationUrl = new URL(
        "/verify-email.html",
        frontendUrl
      );

      verificationUrl.searchParams.set("token", token);

      await transporter.sendMail({
        from,
        to,
        subject: "Verify your CipherNest email address",
        text: [
          "Welcome to CipherNest SecureShare.",
          "",
          "Please verify your email address using this link:",
          verificationUrl.toString(),
          "",
          "This verification link expires in 24 hours.",
          "",
          "If you did not create this account, you can ignore this email.",
        ].join("\n"),
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 560px; margin: 0 auto; color: #263746;">
            <h2 style="color: #315f82;">Welcome to CipherNest</h2>
            <p>Thank you for registering for CipherNest SecureShare.</p>
            <p>Please verify your email address by clicking the button below.</p>
            <p style="margin: 28px 0;">
              <a
                href="${verificationUrl.toString()}"
                style="background: #315f82; color: #ffffff; padding: 12px 22px; text-decoration: none; border-radius: 4px; display: inline-block;"
              >
                Verify email address
              </a>
            </p>
            <p>This verification link expires in 24 hours.</p>
            <p>If you did not create this account, you can ignore this email.</p>
            <hr style="border: 0; border-top: 1px solid #e5e9ed; margin-top: 28px;">
            <p style="font-size: 12px; color: #718096;">
              CipherNest SecureShare
            </p>
          </div>
        `,
      });
    },
  };
}

function createGmailTransport() {
  const {
    SMTP_HOST,
    SMTP_PORT,
    SMTP_SECURE,
    SMTP_USER,
    SMTP_PASS,
  } = process.env;

  if (!SMTP_HOST || !SMTP_USER || !SMTP_PASS) {
    throw new Error("Gmail SMTP environment variables are missing.");
  }

  return nodemailer.createTransport({
    host: SMTP_HOST,
    port: Number(SMTP_PORT || 465),
    secure: SMTP_SECURE === "true",
    auth: {
      user: SMTP_USER,
      pass: SMTP_PASS,
    },
  });
}

function createDefaultEmailService() {
  return createEmailService({
    transporter: createGmailTransport(),
    frontendUrl: process.env.FRONTEND_URL,
    from: process.env.EMAIL_FROM,
  });
}

module.exports = {
  createEmailService,
  createGmailTransport,
  createDefaultEmailService,
};
