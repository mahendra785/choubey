"use client";
import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { useRouter } from "next/navigation";
import { api } from "@/lib/api";
import type { Role, User } from "@/lib/types";

interface AuthState { user: User | null; loading: boolean; logout: () => Promise<void>; can: (...roles: Role[]) => boolean }
const Ctx = createContext<AuthState>({ user: null, loading: true, logout: async () => {}, can: () => false });
export const useAuth = () => useContext(Ctx);

/** UI convenience only: the server enforces every permission. */
export function AuthProvider({ children }: { children: ReactNode }) {
  const router = useRouter();
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.me().then(setUser).catch(() => router.replace("/login")).finally(() => setLoading(false));
  }, [router]);

  const logout = useCallback(async () => {
    try { await api.logout(); } finally { setUser(null); router.replace("/login"); }
  }, [router]);

  const can = useCallback((...roles: Role[]) => !!user && roles.includes(user.role), [user]);
  return <Ctx.Provider value={{ user, loading, logout, can }}>{children}</Ctx.Provider>;
}
