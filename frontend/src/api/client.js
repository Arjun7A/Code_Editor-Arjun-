import axios from 'axios';

const API_BASE_URL = import.meta.env.VITE_API_URL || '/api';

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// PR Analysis
export const analyzePR = async (prData) => {
  const response = await api.post('/analyze', prData);
  return response.data;
};

export const getPRResults = async (prId) => {
  const response = await api.get(`/results/${prId}`);
  return response.data;
};

export const getAllResults = async (skip = 0, limit = 10) => {
  const response = await api.get(`/results?skip=${skip}&limit=${limit}`);
  return response.data;
};

// Health Check
export const healthCheck = async () => {
  const response = await api.get('/health');
  return response.data;
};

// ML Risk Prediction
export const predictRisk = async (features) => {
  const response = await api.post('/predict_risk', features);
  return response.data;
};

// GitHub Repo ML Analysis
export const analyzeGitHub = async (repo, numPrs = 10) => {
  const response = await api.post('/analyze_github', { repo, num_prs: numPrs });
  return response.data;
};

export default api;
