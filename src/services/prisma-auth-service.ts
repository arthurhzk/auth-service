import { hash, compare } from "bcryptjs";
import prisma from "../infra/prisma.ts";
import createError from "@fastify/error";
import { StatusCodes } from "http-status-codes";
import { dispatchRegistrationNotification } from "../broker/messages/send-register-notification.ts";
const UserExists = createError(
  "USER_EXISTS",
  "User already exists",
  StatusCodes.CONFLICT
);
const PasswordMismatch = createError(
  "PASSWORD_MISMATCH",
  "Passwords do not match",
  StatusCodes.BAD_REQUEST
);
const UserNotFound = createError(
  "USER_NOT_FOUND",
  "User not found",
  StatusCodes.NOT_FOUND
);
const InvalidCredentials = createError(
  "INVALID_CREDENTIALS",
  "Invalid credentials",
  StatusCodes.UNAUTHORIZED
);

export class PrismaAuthService {
  private readonly SALT = 10;

  async createUser(
    email: string,
    name: string,
    password: string,
    passwordConfirm: string
  ): Promise<boolean> {
    const userExists = await this.findUserByEmail(email);
    if (userExists) throw new UserExists();
    if (password !== passwordConfirm) throw new PasswordMismatch();

    const user = await prisma.user.create({
      data: {
        email,
        name,
        passwordHash: await hash(password, this.SALT),
      },
    });

    return !!user;
  }

  async loginUser(email: string, password: string): Promise<boolean> {
    const user = await this.findUserByEmail(email);
    if (!user) throw new UserNotFound();

    const isValidPassword = await compare(password, user.passwordHash);
    if (!isValidPassword) throw new InvalidCredentials();

    return true;
  }

  private async findUserByEmail(email: string) {
    return prisma.user.findUnique({
      where: { email },
    });
  }
  async verifyEmail(email: string) {
    const user = await this.findUserByEmail(email);
    if (!user) throw new UserNotFound();

    if (user.isEmailVerified) {
      throw new Error("Email already verified");
    }
    await prisma.user.update({
      where: { email },
      data: { isEmailVerified: true },
    });
  }
}
