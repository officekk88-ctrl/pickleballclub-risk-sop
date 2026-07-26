"use server";

import { redirect } from "next/navigation";
import { headers } from "next/headers";
import { z } from "zod";
import { setSession } from "@/lib/auth";
import { clearLoginFailures, loginBlockedForMs, recordLoginFailure } from "@/lib/login-security";
import { authenticateUser } from "@/lib/mvp-store";

export type LoginState = { error?: string };

const loginSchema = z.object({
  email: z.string().trim().email(),
  password: z.string().min(1),
});

export async function login(_: LoginState, formData: FormData): Promise<LoginState> {
  const input = loginSchema.safeParse({
    email: formData.get("email"),
    password: formData.get("password"),
  });

  if (!input.success) return { error: "请输入有效的邮箱和密码。" };

  const requestHeaders = await headers();
  const address = requestHeaders.get("x-forwarded-for")?.split(",")[0]?.trim()
    || requestHeaders.get("x-real-ip")
    || "unknown";
  if (loginBlockedForMs(input.data.email, address) > 0) {
    return { error: "登录尝试过于频繁，请稍后再试。" };
  }

  const user = await authenticateUser(input.data.email, input.data.password);
  if (!user) {
    recordLoginFailure(input.data.email, address);
    return { error: "邮箱或密码不正确。" };
  }

  clearLoginFailures(user.email);
  await setSession(user.email, user.role);
  redirect("/dashboard");
}

export async function logout(): Promise<void> {
  const { clearSession } = await import("@/lib/auth");
  await clearSession();
  redirect("/login");
}
