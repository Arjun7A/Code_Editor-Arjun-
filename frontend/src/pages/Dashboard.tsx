import { useEffect, useMemo, useState } from "react";
import { RefreshCw } from "lucide-react";
import { Header } from "@/components/layout/header";
import { Sidebar } from "@/components/layout/sidebar";
import { StatsCards } from "@/components/dashboard/stats-cards";
import { FilterBar } from "@/components/dashboard/filter-bar";
import { PRList } from "@/components/dashboard/pr-list";
import { Button } from "@/components/ui/button";
import {
  RiskTrendsChart,
  VerdictDistributionChart,
  SeverityBreakdownChart,
  ScannerMetricsChart,
} from "@/components/dashboard/charts";
import { getDashboardStats, getDataset } from "@/lib/api";
import type { DashboardStats, FilterOptions, ScanRecord } from "@/lib/types";
import {
  buildRiskTrends,
  buildSeverityBreakdown,
  buildToolMetrics,
  buildVerdictDistribution,
  filterScans,
  getQuickFilterCounts,
  getRepoFullName,
  getRepoName,
  getTotalIssues,
  sortScans,
  toRecentPRRow,
} from "@/lib/scan-utils";

export default function DashboardPage() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [selectedFilter, setSelectedFilter] = useState("all");
  const [selectedRepo, setSelectedRepo] = useState("all");
  const [filters, setFilters] = useState<FilterOptions>({
    repository: "all",
    quickFilter: "all",
    search: "",
  });

  useEffect(() => {
    void loadDashboardData();
  }, []);

  async function loadDashboardData() {
    setLoading(true);
    setIsRefreshing(true);
    setError(null);

    try {
      const [statsResponse, datasetResponse] = await Promise.all([
        getDashboardStats(),
        getDataset(),
      ]);

      const orderedScans = sortScans(datasetResponse.scans);
      const computedTotalIssues = orderedScans.reduce(
        (sum, scan) => sum + getTotalIssues(scan),
        0
      );

      setScans(orderedScans);
      setStats({
        totalScans: statsResponse.total_scans || datasetResponse.total,
        totalIssues:
          statsResponse.total_issues > 0 ? statsResponse.total_issues : computedTotalIssues,
      });
    } catch (loadError) {
      const message =
        loadError instanceof Error
          ? loadError.message
          : "We couldn't load dashboard data right now.";

      setError(message);
      setStats(null);
      setScans([]);
    } finally {
      setLoading(false);
      setIsRefreshing(false);
    }
  }

  const filteredScans = useMemo(
    () => filterScans(scans, filters),
    [filters, scans]
  );

  const recentRows = useMemo(
    () => filteredScans.map(toRecentPRRow),
    [filteredScans]
  );

  const quickFilterCounts = useMemo(() => getQuickFilterCounts(scans), [scans]);

  const repositories = useMemo(
    () =>
      Array.from(
        new Map(
          scans.map((scan) => {
            const fullName = getRepoFullName(scan.repo_url);
            return [
              fullName,
              {
                id: fullName,
                name: getRepoName(scan.repo_url),
                owner: fullName.split("/")[0] ?? "",
                prCount: scans.filter(
                  (candidate) => getRepoFullName(candidate.repo_url) === fullName
                ).length,
              },
            ];
          })
        ).values()
      ),
    [scans]
  );

  const chartScans = filteredScans;

  return (
    <div className="min-h-screen bg-background">
      <Header />

      <div className="flex">
        <Sidebar
          onFilterChange={(filter) => {
            setSelectedFilter(filter);
            setFilters((current) => ({
              ...current,
              quickFilter: filter === "all" ? "all" : (filter as FilterOptions["quickFilter"]),
            }));
          }}
          onRepoSelect={(repoId) => {
            setSelectedRepo(repoId);
            setFilters((current) => ({
              ...current,
              repository: repoId === "all" ? "all" : repoId,
            }));
          }}
          selectedFilter={selectedFilter}
          selectedRepo={selectedRepo}
          repos={repositories}
          filterCounts={quickFilterCounts}
        />

        <main className="flex-1 overflow-auto">
          <div className="mx-auto max-w-screen-2xl px-4 py-6 lg:px-8">
            <div className="mb-8 flex items-center justify-between">
              <div>
                <h1 className="text-2xl font-bold tracking-tight text-foreground">
                  Security Dashboard
                </h1>
                <p className="mt-1 text-muted-foreground">
                  Live scan history and issue trends from the SecureAudit backend.
                </p>
              </div>

              <Button
                variant="outline"
                size="sm"
                onClick={() => void loadDashboardData()}
                disabled={isRefreshing}
                className="gap-2"
              >
                <RefreshCw className={`h-4 w-4 ${isRefreshing ? "animate-spin" : ""}`} />
                Refresh
              </Button>
            </div>

            {error ? (
              <div className="mb-6 rounded-xl border border-border/60 bg-card/70 p-4 text-sm text-muted-foreground">
                <p className="font-medium text-foreground">Backend offline</p>
                <p className="mt-1">{error}</p>
              </div>
            ) : null}

            <section className="mb-8">
              <StatsCards stats={stats} loading={loading} />
            </section>

            <section className="mb-6">
              <FilterBar
                filters={filters}
                onFiltersChange={(nextFilters) => setFilters(nextFilters)}
                repositories={repositories.map((repo) => repo.id)}
              />
            </section>

            <section className="mb-8 grid gap-4 lg:grid-cols-2 xl:grid-cols-4">
              <RiskTrendsChart
                data={buildRiskTrends(chartScans)}
                loading={loading}
              />
              <VerdictDistributionChart
                data={buildVerdictDistribution(chartScans)}
                loading={loading}
              />
              <SeverityBreakdownChart
                data={buildSeverityBreakdown(chartScans)}
                loading={loading}
              />
              <ScannerMetricsChart
                data={buildToolMetrics(chartScans)}
                loading={loading}
              />
            </section>

            <section>
              <PRList rows={recentRows} loading={loading} />
            </section>
          </div>
        </main>
      </div>
    </div>
  );
}
