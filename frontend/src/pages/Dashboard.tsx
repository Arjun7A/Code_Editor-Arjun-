import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Header } from "@/components/layout/header";
import { Sidebar } from "@/components/layout/sidebar";
import { StatsCards } from "@/components/dashboard/stats-cards";
import { PRList } from "@/components/dashboard/pr-list";
import { FilterBar } from "@/components/dashboard/filter-bar";
import {
  RiskTrendsChart,
  VerdictDistributionChart,
  SeverityBreakdownChart,
  ScannerMetricsChart,
} from "@/components/dashboard/charts";
import {
  fetchDashboardStats,
  fetchPRList,
  fetchRiskTrends,
  fetchVerdictDistribution,
  fetchSeverityBreakdown,
  fetchScannerMetrics,
} from "@/lib/api";
import type {
  DashboardStats,
  PRAnalysis,
  ChartDataPoint,
  VerdictDistribution,
  SeverityBreakdown,
  FilterOptions,
} from "@/lib/types";

export default function DashboardPage() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [prs, setPRs] = useState<PRAnalysis[]>([]);
  const [riskTrends, setRiskTrends] = useState<ChartDataPoint[]>([]);
  const [verdictDist, setVerdictDist] = useState<VerdictDistribution[]>([]);
  const [severityBreakdown, setSeverityBreakdown] = useState<SeverityBreakdown[]>([]);
  const [scannerMetrics, setScannerMetrics] = useState<
    { name: string; avgTime: number; successRate: number }[]
  >([]);
  const [loading, setLoading] = useState(true);
  const [chartsLoading, setChartsLoading] = useState(true);
  const [viewMode, setViewMode] = useState<"grid" | "table">("grid");
  const [filters, setFilters] = useState<FilterOptions>({
    verdict: "all",
    riskLevel: "all",
    repository: "all",
    search: "",
  });
  const [selectedFilter, setSelectedFilter] = useState("all");
  const [selectedRepo, setSelectedRepo] = useState("all");

  // Fetch initial data
  useEffect(() => {
    async function loadData() {
      setLoading(true);
      try {
        const [statsData, prsData] = await Promise.all([
          fetchDashboardStats(),
          fetchPRList(filters),
        ]);
        setStats(statsData);
        setPRs(prsData);
      } catch (error) {
        console.error("[v0] Error loading dashboard data:", error);
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, [filters]);

  // Fetch chart data
  useEffect(() => {
    async function loadCharts() {
      setChartsLoading(true);
      try {
        const [trends, verdict, severity, scanner] = await Promise.all([
          fetchRiskTrends(),
          fetchVerdictDistribution(),
          fetchSeverityBreakdown(),
          fetchScannerMetrics(),
        ]);
        setRiskTrends(trends);
        setVerdictDist(verdict);
        setSeverityBreakdown(severity);
        setScannerMetrics(scanner);
      } catch (error) {
        console.error("[v0] Error loading charts:", error);
      } finally {
        setChartsLoading(false);
      }
    }
    loadCharts();
  }, []);

  const handleFilterChange = (filter: string) => {
    setSelectedFilter(filter);
    if (filter === "all") {
      setFilters({ ...filters, verdict: "all" });
    } else {
      setFilters({ ...filters, verdict: filter as FilterOptions["verdict"] });
    }
  };

  const handleRepoSelect = (repoId: string) => {
    setSelectedRepo(repoId);
    setFilters({
      ...filters,
      repository: repoId === "all" ? "all" : repoId,
    });
  };

  return (
    <div className="min-h-screen bg-background">
      <Header />

      <div className="flex">
        <Sidebar
          onFilterChange={handleFilterChange}
          onRepoSelect={handleRepoSelect}
          selectedFilter={selectedFilter}
          selectedRepo={selectedRepo}
        />

        <main className="flex-1 overflow-auto">
          <div className="mx-auto max-w-screen-2xl px-4 py-6 lg:px-8">
            {/* Page Header */}
            <motion.div
              initial={{ opacity: 0, y: -20 }}
              animate={{ opacity: 1, y: 0 }}
              className="mb-8"
            >
              <h1 className="text-2xl font-bold tracking-tight text-foreground">
                Security Dashboard
              </h1>
              <p className="mt-1 text-muted-foreground">
                Monitor and analyze pull request security across your
                repositories
              </p>
            </motion.div>

            {/* Stats Cards */}
            <section className="mb-8">
              <StatsCards stats={stats} loading={loading} />
            </section>

            {/* Charts Grid */}
            <section className="mb-8 grid gap-4 lg:grid-cols-2 xl:grid-cols-4">
              <RiskTrendsChart data={riskTrends} loading={chartsLoading} />
              <VerdictDistributionChart
                data={verdictDist}
                loading={chartsLoading}
              />
              <SeverityBreakdownChart
                data={severityBreakdown}
                loading={chartsLoading}
              />
              <ScannerMetricsChart
                data={scannerMetrics}
                loading={chartsLoading}
              />
            </section>

            {/* Filter Bar */}
            <section className="mb-6">
              <FilterBar
                filters={filters}
                onFiltersChange={setFilters}
                repositories={[
                  "api-gateway",
                  "web-app",
                  "auth-service",
                  "payment-service",
                ]}
              />
            </section>

            {/* PR List */}
            <section>
              <PRList
                prs={prs}
                loading={loading}
                viewMode={viewMode}
                onViewModeChange={setViewMode}
              />
            </section>
          </div>
        </main>
      </div>
    </div>
  );
}
