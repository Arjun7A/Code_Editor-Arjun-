'use client';

import React, { createContext, useContext, useState } from "react";
import type { FilterOptions, PRAnalysis } from "./types";

export interface AppState {
  filters: FilterOptions;
  selectedPR: PRAnalysis | null;
  sidebarCollapsed: boolean;
  theme: "dark" | "light";
}

export const defaultState: AppState = {
  filters: {
    verdict: "all",
    riskLevel: "all",
    repository: "all",
    search: "",
  },
  selectedPR: null,
  sidebarCollapsed: false,
  theme: "dark",
};

export const AppContext = createContext<{
  state: AppState;
  setState: React.Dispatch<React.SetStateAction<AppState>>;
}>({
  state: defaultState,
  setState: () => {},
});

export const useAppState = () => useContext(AppContext);

export function StoreProvider({ children }: { children: React.ReactNode }) {
  const [state, setState] = useState<AppState>(defaultState);

  return (
    <AppContext.Provider value={{ state, setState }}>
      {children}
    </AppContext.Provider>
  );
}
