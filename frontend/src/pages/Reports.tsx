import { useState } from "react";
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
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import {
  FileText,
  Download,
  Calendar,
  TrendingUp,
  TrendingDown,
  Shield,
  Bug,
  Clock,
  GitPullRequest,
  BarChart3,
  PieChart,
  Activity,
  Users,
  Zap,
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
import { cn } from "@/lib/utils";
import { AnimatedCounter } from "@/components/ui/animated-counter";

const riskTrendData = [
  { month: "Jul", critical: 12, high: 28, medium: 45, low: 89 },
  { month: "Aug", critical: 8, high: 32, medium: 52, low: 95 },
  { month: "Sep", critical: 15, high: 25, medium: 48, low: 88 },
  { month: "Oct", critical: 6, high: 22, medium: 38, low: 72 },
  { month: "Nov", critical: 4, high: 18, medium: 32, low: 65 },
  { month: "Dec", critical: 3, high: 15, medium: 28, low: 58 },
  { month: "Jan", critical: 2, high: 12, medium: 25, low: 52 },
];

const prVolumeData = [
  { week: "W1", analyzed: 45, approved: 38, rejected: 7 },
  { week: "W2", analyzed: 52, approved: 44, rejected: 8 },
  { week: "W3", analyzed: 38, approved: 35, rejected: 3 },
  { week: "W4", analyzed: 61, approved: 52, rejected: 9 },
];

const vulnDistribution = [
  { name: "SQL Injection", value: 23, color: "#f43f5e" },
  { name: "XSS", value: 31, color: "#f59e0b" },
  { name: "Auth Issues", value: 18, color: "#3b82f6" },
  { name: "Data Exposure", value: 15, color: "#10b981" },
  { name: "Misc", value: 13, color: "#6b7280" },
];

const teamMetrics = [
  {
    name: "Frontend Team",
    prs: 45,
    avgRisk: 32,
    criticals: 2,
    trend: "down",
  },
  { name: "Backend Team", prs: 62, avgRisk: 48, criticals: 5, trend: "up" },
  { name: "DevOps Team", prs: 28, avgRisk: 25, criticals: 0, trend: "down" },
  { name: "Mobile Team", prs: 34, avgRisk: 38, criticals: 1, trend: "down" },
];

const recentReports = [
  {
    id: "1",
    name: "Monthly Security Summary - January 2024",
    type: "Monthly",
    date: "Jan 31, 2024",
    status: "ready",
  },
  {
    id: "2",
    name: "Weekly Risk Analysis - Week 4",
    type: "Weekly",
    date: "Jan 28, 2024",
    status: "ready",
  },
  {
    id: "3",
    name: "Compliance Audit Report - Q4 2023",
    type: "Quarterly",
    date: "Jan 15, 2024",
    status: "ready",
  },
  {
    id: "4",
    name: "Custom: Critical Vulnerabilities",
    type: "Custom",
    date: "Jan 10, 2024",
    status: "ready",
  },
];

export default function ReportsPage() {
  const [dateRange, setDateRange] = useState("30d");

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

            {/* Summary Cards */}
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
              <Card className="border-border/50 bg-card/50 backdrop-blur-sm">
                <CardContent className="pt-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm text-muted-foreground">
                        Total PRs Analyzed
                      </p>
                      <p className="mt-1 text-3xl font-bold text-foreground">
                        <AnimatedCounter value={1284} />
                      </p>
                      <p className="mt-1 flex items-center text-xs text-success">
                        <TrendingUp className="mr-1 h-3 w-3" />
                        +12.5% from last period
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
                        <AnimatedCounter value={247} />
                      </p>
                      <p className="mt-1 flex items-center text-xs text-success">
                        <TrendingDown className="mr-1 h-3 w-3" />
                        -23% from last period
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
                        Avg. Analysis Time
                      </p>
                      <p className="mt-1 text-3xl font-bold text-foreground">
                        42s
                      </p>
                      <p className="mt-1 flex items-center text-xs text-success">
                        <TrendingDown className="mr-1 h-3 w-3" />
                        -8s from last period
                      </p>
                    </div>
                    <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-accent/10">
                      <Clock className="h-6 w-6 text-accent" />
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card className="border-border/50 bg-card/50 backdrop-blur-sm">
                <CardContent className="pt-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm text-muted-foreground">
                        Security Score
                      </p>
                      <p className="mt-1 text-3xl font-bold text-success">
                        87/100
                      </p>
                      <p className="mt-1 flex items-center text-xs text-success">
                        <TrendingUp className="mr-1 h-3 w-3" />
                        +5 from last period
                      </p>
                    </div>
                    <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-success/10">
                      <Shield className="h-6 w-6 text-success" />
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* Charts Row */}
            <div className="grid gap-6 lg:grid-cols-2">
              {/* Risk Trend Chart */}
              <Card className="border-border/50 bg-card/50 backdrop-blur-sm">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Activity className="h-5 w-5 text-primary" />
                    Risk Trend Over Time
                  </CardTitle>
                  <CardDescription>
                    Monthly vulnerability trends by severity
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="h-80">
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart data={riskTrendData}>
                        <defs>
                          <linearGradient
                            id="criticalGrad"
                            x1="0"
                            y1="0"
                            x2="0"
                            y2="1"
                          >
                            <stop
                              offset="5%"
                              stopColor="#f43f5e"
                              stopOpacity={0.3}
                            />
                            <stop
                              offset="95%"
                              stopColor="#f43f5e"
                              stopOpacity={0}
                            />
                          </linearGradient>
                          <linearGradient
                            id="highGrad"
                            x1="0"
                            y1="0"
                            x2="0"
                            y2="1"
                          >
                            <stop
                              offset="5%"
                              stopColor="#f59e0b"
                              stopOpacity={0.3}
                            />
                            <stop
                              offset="95%"
                              stopColor="#f59e0b"
                              stopOpacity={0}
                            />
                          </linearGradient>
                          <linearGradient
                            id="mediumGrad"
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
                          dataKey="month"
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
                          dataKey="critical"
                          stroke="#f43f5e"
                          fill="url(#criticalGrad)"
                          strokeWidth={2}
                        />
                        <Area
                          type="monotone"
                          dataKey="high"
                          stroke="#f59e0b"
                          fill="url(#highGrad)"
                          strokeWidth={2}
                        />
                        <Area
                          type="monotone"
                          dataKey="medium"
                          stroke="#3b82f6"
                          fill="url(#mediumGrad)"
                          strokeWidth={2}
                        />
                      </AreaChart>
                    </ResponsiveContainer>
                  </div>
                  <div className="mt-4 flex justify-center gap-6">
                    <div className="flex items-center gap-2">
                      <div className="h-3 w-3 rounded-full bg-[#f43f5e]" />
                      <span className="text-sm text-muted-foreground">
                        Critical
                      </span>
                    </div>
                    <div className="flex items-center gap-2">
                      <div className="h-3 w-3 rounded-full bg-[#f59e0b]" />
                      <span className="text-sm text-muted-foreground">
                        High
                      </span>
                    </div>
                    <div className="flex items-center gap-2">
                      <div className="h-3 w-3 rounded-full bg-[#3b82f6]" />
                      <span className="text-sm text-muted-foreground">
                        Medium
                      </span>
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* Vulnerability Distribution */}
              <Card className="border-border/50 bg-card/50 backdrop-blur-sm">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <PieChart className="h-5 w-5 text-primary" />
                    Vulnerability Distribution
                  </CardTitle>
                  <CardDescription>
                    Breakdown by vulnerability type
                  </CardDescription>
                </CardHeader>
                <CardContent>
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
                            <Cell key={`cell-${index}`} fill={entry.color} />
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
                          {item.value}%
                        </span>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* PR Volume and Team Metrics */}
            <div className="grid gap-6 lg:grid-cols-3">
              {/* PR Volume */}
              <Card className="border-border/50 bg-card/50 backdrop-blur-sm lg:col-span-2">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <BarChart3 className="h-5 w-5 text-primary" />
                    PR Analysis Volume
                  </CardTitle>
                  <CardDescription>
                    Weekly breakdown of analyzed pull requests
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="h-64">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={prVolumeData} barGap={8}>
                        <CartesianGrid
                          strokeDasharray="3 3"
                          stroke="hsl(var(--border))"
                          opacity={0.3}
                        />
                        <XAxis
                          dataKey="week"
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
                          dataKey="approved"
                          fill="#10b981"
                          radius={[4, 4, 0, 0]}
                        />
                        <Bar
                          dataKey="rejected"
                          fill="#f43f5e"
                          radius={[4, 4, 0, 0]}
                        />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                  <div className="mt-4 flex justify-center gap-6">
                    <div className="flex items-center gap-2">
                      <div className="h-3 w-3 rounded-full bg-[#10b981]" />
                      <span className="text-sm text-muted-foreground">
                        Approved
                      </span>
                    </div>
                    <div className="flex items-center gap-2">
                      <div className="h-3 w-3 rounded-full bg-[#f43f5e]" />
                      <span className="text-sm text-muted-foreground">
                        Rejected
                      </span>
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* Team Metrics */}
              <Card className="border-border/50 bg-card/50 backdrop-blur-sm">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Users className="h-5 w-5 text-primary" />
                    Team Performance
                  </CardTitle>
                  <CardDescription>Risk metrics by team</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  {teamMetrics.map((team, index) => (
                    <div
                      key={index}
                      className="rounded-lg border border-border/50 p-3"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-medium text-foreground">
                          {team.name}
                        </span>
                        <div className="flex items-center gap-1">
                          {team.trend === "down" ? (
                            <TrendingDown className="h-4 w-4 text-success" />
                          ) : (
                            <TrendingUp className="h-4 w-4 text-warning" />
                          )}
                          <span
                            className={cn(
                              "text-sm",
                              team.trend === "down"
                                ? "text-success"
                                : "text-warning"
                            )}
                          >
                            {team.avgRisk}%
                          </span>
                        </div>
                      </div>
                      <div className="mt-2 flex items-center gap-4 text-xs text-muted-foreground">
                        <span>{team.prs} PRs</span>
                        <span
                          className={cn(
                            team.criticals > 0 && "text-critical font-medium"
                          )}
                        >
                          {team.criticals} critical
                        </span>
                      </div>
                      <Progress
                        value={team.avgRisk}
                        className="mt-2 h-1.5"
                      />
                    </div>
                  ))}
                </CardContent>
              </Card>
            </div>

            {/* Recent Reports */}
            <Card className="border-border/50 bg-card/50 backdrop-blur-sm">
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="flex items-center gap-2">
                      <FileText className="h-5 w-5 text-primary" />
                      Generated Reports
                    </CardTitle>
                    <CardDescription>
                      Download or schedule security reports
                    </CardDescription>
                  </div>
                  <Button variant="outline" className="gap-2 bg-transparent">
                    <Zap className="h-4 w-4" />
                    Generate Custom Report
                  </Button>
                </div>
              </CardHeader>
              <CardContent>
                <div className="divide-y divide-border/50">
                  {recentReports.map((report) => (
                    <div
                      key={report.id}
                      className="flex items-center justify-between py-4 first:pt-0 last:pb-0"
                    >
                      <div className="flex items-center gap-4">
                        <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
                          <FileText className="h-5 w-5 text-primary" />
                        </div>
                        <div>
                          <p className="font-medium text-foreground">
                            {report.name}
                          </p>
                          <p className="text-sm text-muted-foreground">
                            {report.date}
                          </p>
                        </div>
                      </div>
                      <div className="flex items-center gap-3">
                        <Badge variant="secondary">{report.type}</Badge>
                        <Button variant="outline" size="sm" className="gap-2 bg-transparent">
                          <Download className="h-4 w-4" />
                          Download
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>
        </main>
      </div>
    </div>
  );
}
