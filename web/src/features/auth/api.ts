import { jsonRequest, request } from "../../app/apiClient";

export type SessionUser = {
  username: string;
  name: string;
  role: "admin";
};

export type Session = {
  authenticated: true;
  user: SessionUser;
};

export function login(username: string, password: string) {
  return request<Session>(
    "/api/v1/login",
    jsonRequest("POST", { username, password }),
  );
}

export function getSession() {
  return request<Session>("/api/v1/session");
}

export function logout() {
  return request<void>("/api/v1/logout", { method: "POST" });
}

export function changePassword(currentPassword: string, newPassword: string) {
  return request<void>(
    "/api/v1/account/password",
    jsonRequest("PUT", { currentPassword, newPassword }),
  );
}
