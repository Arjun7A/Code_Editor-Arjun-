import { useState, useEffect } from "react";
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
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  TrendingUp,
  Shield,
  Bug,
  GitPullRequest,
  BarChart3,
  PieChart,
  Activity,
  Download,
  Calendar,
  AlertTriangle,
} from "lucide-react";
import {
  AreaChart,
  Area,
  BarChart,
  Bar,
  PieChart as RePieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import { AnimatedCounter } from "@/components/ui/animated-counter";
import {
  fetchDashboardStats,
  fetchRiskTrends,
  fetchSeverityBreakdown,
  fetchVerdictDistribution,
} from "@/lib/api";
import type {
  DashboardStats,
  ChartDataPoint,
  SeverityBreakdown,
  VerdictDistribution,
} from "@/lib/types";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#f43f5e",
  high: "#f59e0b",
  medium: "#3b82f6",
  low: "#10b981",
};

const VERDICT_COLORS: Record<string, string> = {
  approved: "#10b981",
  manual_review: "#f59e0b",
  blocked: "#f43f5e",
};

export default function ReportsPage() {
  const [dateRange, setDateRange] = useState("30d");
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [riskTrends, setRiskTrends] = useState<ChartDataPoint[]>([]);
  const [severityBreakdown, setSeverityBreakdown] = useState<SeverityBreakdown[]>([]);
  const [verdictDist, setVerdictDist] = useState<VerdictDistribution[]>([]);
  const [loading, setLoading] = useState(true);
  const [apiError, setApiError] = useState<string | null>(null);

  useEffect(() => {
    async function loadData() {
      setLoading(true);
      setApiError(null);
      try {
        const [statsData, trends, severity, verdict] = await Promise.all([
          fetchDashboardStats(),
          fetchRiskTrends(),
          fetchSeverityBreakdown(),
          fetchVerdictDistribution(),
        ]);
        setStats(statsData);
        setRiskTrends(trends);
        setSeverityBreakdown(severity);
        setVerdictDist(verdict);
      } catch (error) {
        const message = error instanceof Error ? error.message : "Failed to load reports data";
        console.error("Error loading reports data:", error);
        setApiError(message);
        setStats(null);
        setRiskTrends([]);
        setSeverityBreakdown([]);
        setVerdictDist([]);
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, []);

  const totalVulnerabilities = severityBreakdown.reduce(
    (sum, s) => sum + s.count,
    0
  );

  // Convert severity breakdown to pie chart data
  const vulnDistribution = severityBreakdown
    .filter((s) => s.count > 0)
    .map((s) => ({
      name: s.severity.charAt(0).toUpperCase() + s.severity.slice(1),
      value: s.count,
      color: SEVERITY_COLORS[s.severity] || "#6b7280",
    }));

  // Convert verdict distribution to bar chart data
  const verdictBarData = verdictDist.map((v) => ({
    verdict: v.verdict === "approved" ? "Approved" : v.verdict === "blocked" ? "Blocked" : "Manual Review",
    count: v.count,
    fill: VERDICT_COLORS[v.verdict] || "#6b7280",
  }));

  return (
    <div className="flex h-screen bg-background">
      <Sidebar />

      <div className="flex flex-1 flex-col overflow-hidden">
        <Header />

        <main className="flex-1 overflow-y-auto p-6">
          <div className="mx-auto max-w-7xl space-y-6">
            {/* Header */}
            <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
              <div>
                <h1 className="text-3xl font-bold text-foreground">
                  Security Reports
                </h1>
                <p className="mt-1 text-muted-foreground">
                  Comprehensive security analytics and trend analysis
                </p>
              </div>
              <div className="flex items-center gap-3">
                <Select value={dateRange} onValueChange={setDateRange}>
                  <SelectTrigger className="w-40">
                    <Calendar className="mr-2 h-4 w-4" />
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="7d">Last 7 days</SelectItem>
                    <SelectItem value="30d">Last 30 days</SelectItem>
                    <SelectItem value="90d">Last 90 days</SelectItem>
                    <SelectItem value="365d">Last year</SelectItem>
                  </SelectContent>
                </Select>
                <Button className="gap-2">
                  <Download className="h-4 w-4" />
                  Export Report
                </Button>
              </div>
            </div>

            {apiError && (
              <div className="flex items-start gap-3 rounded-lg border border-destructive/30 bg-destructive/10 p-4 text-sm text-destructive">
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                <div>
                  <p className="font-medium">Reports data unavailable</p>
                  <p className="text-destructive/90">{apiError}</p>
                </div>
              </div>
            )}

            {/* Summary Cards — real data from API */}
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
              <Card className="border-border/50 bg-card/50 backdrop-blur-sm">
                <CardContent className="pt-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm text-muted-foreground">
                        Total PRs Analyzed
                      </p>
                      <p className="mt-1 text-3xl font-bold text-foreground">
                        {loading ? "—" : <AnimatedCounter value={stats?.totalPRs ?? 0} />}
                      </p>
                    </div>
                    <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-primary/10">
                      <GitPullRequest className="h-6 w-6 text-primary" />
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card className="border-border/50 bg-card/50 backdrop-blur-sm">
                <CardContent className="pt-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm text-muted-foreground">
                        Vulnerabilities Found
                      </p>
                      <p className="mt-1 text-3xl font-bold text-foreground">
                        {loading ? "—" : <AnimatedCounter value={totalVulnerabilities} />}
                      </p>
                    </div>
                    <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-warning/10">
                      <Bug className="h-6 w-6 text-warning" />
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card className="border-border/50 bg-card/50 backdrop-blur-sm">
                <CardContent className="pt-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm text-muted-foreground">
                        Critical Issues
                      </p>
                      <p className="mt-1 text-3xl font-bold text-foreground">
                        {loading ? "—" : <AnimatedCounter value={stats?.criticalIssues ?? 0} />}
                      </p>
                    </div>
                    <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-destructive/10">
                      <Shield className="h-6 w-6 text-destructive" />
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card className="border-border/50 bg-card/50 backdrop-blur-sm">
                <CardContent className="pt-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm text-muted-foreground">
                        Avg Risk Score
                      </p>
                      <p className="mt-1 text-3xl font-bold text-foreground">
                        {loading
                          ? "—"
                          : `${(stats?.avgRiskScore ?? 0).toFixed(1)}%`}
                      </p>
                    </div>
                    <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-success/10">
                      <TrendingUp className="h-6 w-6 text-success" />
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* Charts Row */}
            <div className="grid gap-6 lg:grid-cols-2">
              {/* Risk Trend Chart — real data */}
              <Card className="border-border/50 bg-card/50 backdrop-blur-sm">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Activity className="h-5 w-5 text-primary" />
                    Risk Trend Over Time
                  </CardTitle>
                  <CardDescription>
                    Daily average risk score (last 30 days)
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  {riskTrends.length === 0 ? (
                    <div className="flex h-80 items-center justify-center text-muted-foreground">
                      No risk trend data yet. Analyze some PRs first.
                    </div>
                  ) : (
                    <div className="h-80">
                      <ResponsiveContainer width="100%" height="100%">
                        <AreaChart data={riskTrends}>
                          <defs>
                            <linearGradient
                              id="riskGrad"
                              x1="0"
                              y1="0"
                              x2="0"
                              y2="1"
                            >
                              <stop
                                offset="5%"
                                stopColor="#3b82f6"
                                stopOpacity={0.3}
                              />
                              <stop
                                offset="95%"
                                stopColor="#3b82f6"
                                stopOpacity={0}
                              />
                            </linearGradient>
                          </defs>
                          <CartesianGrid
                            strokeDasharray="3 3"
                            stroke="hsl(var(--border))"
                            opacity={0.3}
                          />
                          <XAxis
                            dataKey="label"
                            stroke="hsl(var(--muted-foreground))"
                            fontSize={12}
                          />
                          <YAxis
                            stroke="hsl(var(--muted-foreground))"
                            fontSize={12}
                          />
                          <Tooltip
                            contentStyle={{
                              backgroundColor: "hsl(var(--card))",
                              border: "1px solid hsl(var(--border))",
                              borderRadius: "8px",
                            }}
                          />
                          <Area
                            type="monotone"
                            dataKey="value"
                            stroke="#3b82f6"
                            fill="url(#riskGrad)"
                            strokeWidth={2}
                            name="Risk Score"
                          />
                        </AreaChart>
                      </ResponsiveContainer>
                    </div>
                  )}
                </CardContent>
              </Card>

              {/* Vulnerability Distribution — real data */}
              <Card className="border-border/50 bg-card/50 backdrop-blur-sm">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <PieChart className="h-5 w-5 text-primary" />
                    Severity Distribution
                  </CardTitle>
                  <CardDescription>
                    Breakdown by vulnerability severity
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  {vulnDistribution.length === 0 ? (
                    <div className="flex h-80 items-center justify-center text-muted-foreground">
                      No vulnerability data yet. Run some scans first.
                    </div>
                  ) : (
                    <>
                      <div className="h-80">
                        <ResponsiveContainer width="100%" height="100%">
                          <RePieChart>
                            <Pie
                              data={vulnDistribution}
                              cx="50%"
                              cy="50%"
                              innerRadius={60}
                              outerRadius={100}
                              paddingAngle={4}
                              dataKey="value"
                            >
                              {vulnDistribution.map((entry, index) => (
                                <Cell
                                  key={`cell-${index}`}
                                  fill={entry.color}
                                />
                              ))}
                            </Pie>
                            <Tooltip
                              contentStyle={{
                                backgroundColor: "hsl(var(--card))",
                                border: "1px solid hsl(var(--border))",
                                borderRadius: "8px",
                              }}
                            />
                          </RePieChart>
                        </ResponsiveContainer>
                      </div>
                      <div className="mt-4 grid grid-cols-2 gap-2">
                        {vulnDistribution.map((item, index) => (
                          <div key={index} className="flex items-center gap-2">
                            <div
                              className="h-3 w-3 rounded-full"
                              style={{ backgroundColor: item.color }}
                            />
                            <span className="text-sm text-muted-foreground">
                              {item.name}
                            </span>
                            <span className="ml-auto text-sm font-medium text-foreground">
                              {item.value}
                            </span>
                          </div>
                        ))}
                      </div>
                    </>
                  )}
                </CardContent>
              </Card>
            </div>

            {/* Verdict Distribution — real data */}
            <div className="grid gap-6 lg:grid-cols-1">
              <Card className="border-border/50 bg-card/50 backdrop-blur-sm">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <BarChart3 className="h-5 w-5 text-primary" />
                    Verdict Distribution
                  </CardTitle>
                  <CardDescription>
                    Breakdown of analysis verdicts across all PRs
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  {verdictBarData.length === 0 ? (
                    <div className="flex h-64 items-center justify-center text-muted-foreground">
                      No verdict data yet. Analyze some PRs first.
                    </div>
                  ) : (
                    <>
                      <div className="h-64">
                        <ResponsiveContainer width="100%" height="100%">
                          <BarChart data={verdictBarData} barGap={8}>
                            <CartesianGrid
                              strokeDasharray="3 3"
                              stroke="hsl(var(--border))"
                              opacity={0.3}
                            />
                            <XAxis
                              dataKey="verdict"
                              stroke="hsl(var(--muted-foreground))"
                              fontSize={12}
                            />
                            <YAxis
                              stroke="hsl(var(--muted-foreground))"
                              fontSize={12}
                            />
                            <Tooltip
                              contentStyle={{
                                backgroundColor: "hsl(var(--card))",
                                border: "1px solid hsl(var(--border))",
                                borderRadius: "8px",
                              }}
                            />
                            <Bar
                              dataKey="count"
                              radius={[4, 4, 0, 0]}
                            >
                              {verdictBarData.map((entry, index) => (
                                <Cell key={`cell-${index}`} fill={entry.fill} />
                              ))}
                            </Bar>
                          </BarChart>
                        </ResponsiveContainer>
                      </div>
                      <div className="mt-4 flex justify-center gap-6">
                        {verdictBarData.map((item, index) => (
                          <div key={index} className="flex items-center gap-2">
                            <div
                              className="h-3 w-3 rounded-full"
                              style={{ backgroundColor: item.fill }}
                            />
                            <span className="text-sm text-muted-foreground">
                              {item.verdict} ({item.count})
                            </span>
                          </div>
                        ))}
                      </div>
                    </>
                  )}
                </CardContent>
              </Card>
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}
