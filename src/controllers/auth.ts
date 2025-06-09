import type { FastifyRequest, FastifyReply } from "fastify";
import { PrismaAuthService } from "../services/prisma-auth-service.ts";
import { StatusCodes } from "http-status-codes";
import createError from "@fastify/error";
import jwt from "jsonwebtoken";
import { dispatchRegistrationNotification } from "../broker/messages/send-register-notification.ts";

const InvalidRequest = createError(
  "INVALID_REQUEST",
  "Invalid request data",
  StatusCodes.BAD_REQUEST
);

export class AuthController {
  async login(req: FastifyRequest, reply: FastifyReply) {
    const { email, password } = req.body as {
      email: string;
      password: string;
    };

    const requiredFields = [email, password];
    if (requiredFields.some((field) => !field)) {
      throw new InvalidRequest();
    }

    const isLoggedIn = await new PrismaAuthService().loginUser(email, password);

    if (!isLoggedIn) {
      return reply
        .status(StatusCodes.UNAUTHORIZED)
        .send({ message: "Invalid email or password" });
    }
    const token = jwt.sign(
      {
        email,
        password,
      },
      process.env.JWT_SECRET!
    );

    return reply
      .status(StatusCodes.OK)
      .send({ message: "Logged in successfully", token });
  }

  async register(req: FastifyRequest, reply: FastifyReply) {
    const { email, name, password, passwordConfirm } = req.body as {
      email: string;
      name: string;
      password: string;
      passwordConfirm: string;
    };

    const requiredFields = [email, name, password, passwordConfirm];
    if (requiredFields.some((field) => !field)) {
      throw new InvalidRequest();
    }

    const userCreated = await new PrismaAuthService().createUser(
      email,
      name,
      password,
      passwordConfirm
    );

    if (!userCreated) {
      return reply
        .status(StatusCodes.BAD_REQUEST)
        .send({ message: "User already exists or invalid data" });
    }

    const token = jwt.sign(
      {
        email,
      },
      process.env.JWT_SECRET!,
      { expiresIn: "30m" }
    );

    dispatchRegistrationNotification(token);
    return reply
      .status(StatusCodes.CREATED)
      .send({ message: "User created successfully" });
  }

  async logout(req: FastifyRequest, reply: FastifyReply) {
    return reply
      .status(StatusCodes.OK)
      .send({ message: "Logged out successfully" });
  }

  async verifyEmail(req: FastifyRequest, reply: FastifyReply) {
    const { token } = req.query as { token: string };

    if (!token) {
      return reply
        .status(StatusCodes.BAD_REQUEST)
        .send({ message: "Token is required" });
    }

    const { email } = jwt.verify(token, process.env.JWT_SECRET!) as any;
    if (!email) {
      return reply
        .status(StatusCodes.BAD_REQUEST)
        .send({ message: "Invalid token" });
    }

    await new PrismaAuthService().verifyEmail(email);

    return reply
      .status(StatusCodes.OK)
      .send({ message: `${email} verified with success!` });
  }
}
