import { registerNotification } from "../channel/register-notification.ts";

export const dispatchRegistrationNotification = (token: string) => {
  registerNotification.sendToQueue("register-notification", Buffer.from(token));
};
