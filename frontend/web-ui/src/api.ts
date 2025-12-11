import axios from "axios";

const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE || "http://localhost:8443",
  timeout: 5000,
});

export type Status = {
  connected: boolean;
  relay_host: string;
  relay_port: number;
  dns_query: string;
  error?: string | null;
};

export const getStatus = async (): Promise<Status> => (await api.get("/status")).data;
export const triggerConnect = async (): Promise<Status> => (await api.post("/connect")).data;
export const triggerDisconnect = async (): Promise<{ disconnected: boolean }> =>
  (await api.post("/disconnect")).data;