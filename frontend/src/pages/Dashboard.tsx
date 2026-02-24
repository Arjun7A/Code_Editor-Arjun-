import { useState, useEffect, useCallback } from "react";
import { motion } from "framer-motion";
import { AlertTriangle, RefreshCw } from "lucide-react";
import { Header } from "@/components/layout/header";
import { Sidebar } from "@/components/layout/sidebar";
import { StatsCards } from "@/components/dashboard/stats-cards";
import { PRList } from "@/components/dashboard/pr-list";
import { FilterBar } from "@/components/dashboard/filter-bar";
import { Button } from "@/components/ui/button";
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
  const [refreshKey, setRefreshKey] = useState(0);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [apiError, setApiError] = useState<string | null>(null);

  const handleManualRefresh = useCallback(() => {
    setRefreshKey((k) => k + 1);
  }, []);

  // Fetch initial data
  useEffect(() => {
    async function loadData() {
      setLoading(true);
      setIsRefreshing(true);
      setApiError(null);
      try {
        const [statsData, prsData] = await Promise.all([
          fetchDashboardStats(),
          fetchPRList(filters),
        ]);
        setStats(statsData);
        setPRs(prsData);
      } catch (error) {
        const message = error instanceof Error ? error.message : "Failed to load dashboard data";
        console.error("[v0] Error loading dashboard data:", error);
        setApiError(message);
        setStats(null);
        setPRs([]);
      } finally {
        setLoading(false);
        setIsRefreshing(false);
      }
    }
    loadData();
  }, [filters, refreshKey]);

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
        const message = error instanceof Error ? error.message : "Failed to load chart data";
        console.error("[v0] Error loading charts:", error);
        setApiError((prev) => prev ?? message);
        setRiskTrends([]);
        setVerdictDist([]);
        setSeverityBreakdown([]);
        setScannerMetrics([]);
      } finally {
        setChartsLoading(false);
      }
    }
    loadCharts();
  }, [refreshKey]);

  // Auto-refresh every 30 seconds
  useEffect(() => {
    const interval = setInterval(() => {
      setRefreshKey((k) => k + 1);
    }, 30_000);
    return () => clearInterval(interval);
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
          filterCounts={{
            all: stats?.totalPRs ?? prs.length,
            approved: stats?.approved ?? prs.filter((p) => p.verdict === "approved").length,
            blocked: stats?.blocked ?? prs.filter((p) => p.verdict === "blocked").length,
            manual_review: stats?.manualReview ?? prs.filter((p) => p.verdict === "manual_review").length,
          }}
          repos={Array.from(
            new Map(prs.map((pr) => [pr.repository.fullName, pr.repository])).values()
          ).map((r) => ({
            id: r.fullName,
            name: r.name,
            owner: r.owner,
            prCount: prs.filter((p) => p.repository.fullName === r.fullName).length,
          }))}
        />

        <main className="flex-1 overflow-auto">
          <div className="mx-auto max-w-screen-2xl px-4 py-6 lg:px-8">
            {/* Page Header */}
            <motion.div
              initial={{ opacity: 0, y: -20 }}
              animate={{ opacity: 1, y: 0 }}
              className="mb-8"
            >
              <div className="flex items-center justify-between">
                <div>
                  <h1 className="text-2xl font-bold tracking-tight text-foreground">
                    Security Dashboard
                  </h1>
                  <p className="mt-1 text-muted-foreground">
                    Monitor and analyze pull request security across your
                    repositories
                  </p>
                </div>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleManualRefresh}
                  disabled={isRefreshing}
                  className="gap-2"
                >
                  <RefreshCw className={`h-4 w-4 ${isRefreshing ? "animate-spin" : ""}`} />
                  Refresh
                </Button>
              </div>
            </motion.div>

            {apiError && (
              <div className="mb-6 flex items-start gap-3 rounded-lg border border-destructive/30 bg-destructive/10 p-4 text-sm text-destructive">
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                <div>
                  <p className="font-medium">Backend unavailable</p>
                  <p className="text-destructive/90">{apiError}</p>
                </div>
              </div>
            )}

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
                repositories={Array.from(
                  new Set(prs.map((pr) => pr.repository.name))
                ).filter(Boolean)}
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
