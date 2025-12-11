import axios from "axios";

const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE || "http://localhost:8443",
  timeout: 5000,
});

export const getStatus = async () => (await api.get("/status")).data;
export const triggerConnect = async () => (await api.post("/connect")).data;
export const triggerDisconnect = async () => (await api.post("/disconnect")).data;
