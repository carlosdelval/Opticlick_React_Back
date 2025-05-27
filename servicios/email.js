// servicios/email.js
import nodemailer from "nodemailer";

export const sendVerificationEmail = async (email, verificationToken) => {
  const verificationUrl = `https://opticlick-6598e.web.app/verify-email?token=${verificationToken}`;

  const transporter = nodemailer.createTransport({
    host: "smtp.mailtrap.io",
    port: 2525,
    auth: {
      user: "8b4bba6319d6de",
      pass: "0aeddd002ca8bf",
    },
  });

  const mailOptions = {
    from: '"OptiClick" <no-reply@opticlick.com>',
    to: email,
    subject: "Verifica tu email",
    html: `
      <h1>¡Gracias por registrarte en OptiClick!</h1>
      <p>Por favor, verifica tu email haciendo clic en el siguiente enlace:</p>
      <a href="${verificationUrl}">${verificationUrl}</a>
    `,
  };

  await transporter.sendMail(mailOptions);
};
