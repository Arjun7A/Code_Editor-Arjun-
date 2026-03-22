import { useEffect, useMemo, useState } from "react";
import { Download } from "lucide-react";
import { Header } from "@/components/layout/header";
import { Sidebar } from "@/components/layout/sidebar";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  RiskTrendsChart,
  ScannerMetricsChart,
  SeverityBreakdownChart,
  VerdictDistributionChart,
} from "@/components/dashboard/charts";
import { getDashboardStats, getDataset } from "@/lib/api";
import type { DashboardStats, ScanRecord } from "@/lib/types";
import {
  buildRiskTrends,
  buildSeverityBreakdown,
  buildToolMetrics,
  buildVerdictDistribution,
  getTotalIssues,
  sortScans,
} from "@/lib/scan-utils";

export default function ReportsPage() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void loadReports();
  }, []);

  async function loadReports() {
    setLoading(true);
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
          : "We couldn't load report data.";
      setError(message);
      setStats(null);
      setScans([]);
    } finally {
      setLoading(false);
    }
  }

  const totalCriticalAndHigh = useMemo(
    () =>
      buildSeverityBreakdown(scans)
        .filter((item) => item.severity === "critical" || item.severity === "high")
        .reduce((sum, item) => sum + item.count, 0),
    [scans]
  );

  return (
    <div className="flex h-screen bg-background">
      <Sidebar />

      <div className="flex flex-1 flex-col overflow-hidden">
        <Header />

        <main className="flex-1 overflow-y-auto p-6">
          <div className="mx-auto max-w-7xl space-y-6">
            <div className="flex items-center justify-between">
              <div>
                <h1 className="text-3xl font-bold text-foreground">Reports</h1>
                <p className="mt-2 text-muted-foreground">
                  Dataset-backed reporting for completed SecureAudit scans.
                </p>
              </div>

              <Button
                variant="outline"
                className="gap-2"
                onClick={() =>
                  downloadJson(scans, `secureaudit-report-${new Date().toISOString().slice(0, 10)}.json`)
                }
              >
                <Download className="h-4 w-4" />
                Export JSON
              </Button>
            </div>

            {error ? (
              <div className="rounded-xl border border-border/60 bg-card/70 p-4 text-sm text-muted-foreground">
                <p className="font-medium text-foreground">Backend offline</p>
                <p className="mt-1">{error}</p>
              </div>
            ) : null}

            <div className="grid gap-4 md:grid-cols-3">
              <SummaryCard
                title="Total Scans"
                value={stats?.totalScans ?? 0}
                description="Saved scan records"
              />
              <SummaryCard
                title="Total Issues"
                value={stats?.totalIssues ?? 0}
                description="All findings across the dataset"
              />
              <SummaryCard
                title="Critical + High"
                value={totalCriticalAndHigh}
                description="Most urgent findings"
              />
            </div>

            <div className="grid gap-4 lg:grid-cols-2 xl:grid-cols-4">
              <RiskTrendsChart data={buildRiskTrends(scans)} loading={loading} />
              <VerdictDistributionChart
                data={buildVerdictDistribution(scans)}
                loading={loading}
              />
              <SeverityBreakdownChart
                data={buildSeverityBreakdown(scans)}
                loading={loading}
              />
              <ScannerMetricsChart
                data={buildToolMetrics(scans)}
                loading={loading}
              />
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}

function SummaryCard({
  title,
  value,
  description,
}: {
  title: string;
  value: number;
  description: string;
}) {
  return (
    <Card className="border-border/60 bg-card/80">
      <CardHeader>
        <CardTitle className="text-base">{title}</CardTitle>
        <CardDescription>{description}</CardDescription>
      </CardHeader>
      <CardContent>
        <p className="text-3xl font-semibold text-foreground">{value}</p>
      </CardContent>
    </Card>
  );
}

function downloadJson(payload: unknown, filename: string) {
  const blob = new Blob([JSON.stringify(payload, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}
