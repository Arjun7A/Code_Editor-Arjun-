"use client";

import { motion } from "framer-motion";
import {
  LineChart,
  Line,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";
import { ChartSkeleton } from "@/components/ui/skeleton-loader";
import type {
  ChartDataPoint,
  VerdictDistribution,
  SeverityBreakdown,
} from "@/lib/types";


const verdictColors = {
  approved: "#22c55e",
  blocked: "#ef4444",
  manual_review: "#f59e0b",
};

const severityColors = {
  critical: "#dc2626",
  high: "#ef4444",
  medium: "#f59e0b",
  low: "#22c55e",
};

interface RiskTrendsChartProps {
  data: ChartDataPoint[];
  loading?: boolean;
}

export function RiskTrendsChart({ data, loading }: RiskTrendsChartProps) {
  if (loading) return <ChartSkeleton />;

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="rounded-xl border border-border bg-card p-5"
    >
      <h3 className="mb-4 text-sm font-semibold text-foreground">
        Risk Score Trends
      </h3>
      <div className="h-64">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={data}>
            <defs>
              <linearGradient id="riskGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid
              strokeDasharray="3 3"
              stroke="var(--border)"
              vertical={false}
            />
            <XAxis
              dataKey="label"
              tick={{ fill: "var(--muted-foreground)", fontSize: 11 }}
              tickLine={false}
              axisLine={false}
            />
            <YAxis
              tick={{ fill: "var(--muted-foreground)", fontSize: 11 }}
              tickLine={false}
              axisLine={false}
              domain={[0, 100]}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: "var(--popover)",
                border: "1px solid var(--border)",
                borderRadius: "8px",
                color: "var(--popover-foreground)",
              }}
              labelStyle={{ color: "var(--muted-foreground)" }}
            />
            <Line
              type="monotone"
              dataKey="value"
              stroke="#3b82f6"
              strokeWidth={2}
              dot={false}
              activeDot={{
                r: 6,
                fill: "#3b82f6",
                stroke: "var(--background)",
                strokeWidth: 2,
              }}
              fill="url(#riskGradient)"
            />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </motion.div>
  );
}

interface VerdictDistributionChartProps {
  data: VerdictDistribution[];
  loading?: boolean;
}

export function VerdictDistributionChart({
  data,
  loading,
}: VerdictDistributionChartProps) {
  if (loading) return <ChartSkeleton />;

  const pieData = data.map((item) => ({
    name:
      item.verdict === "manual_review"
        ? "Manual Review"
        : item.verdict.charAt(0).toUpperCase() + item.verdict.slice(1),
    value: item.count,
    percentage: item.percentage,
    color: verdictColors[item.verdict],
  }));

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: 0.1 }}
      className="rounded-xl border border-border bg-card p-5"
    >
      <h3 className="mb-4 text-sm font-semibold text-foreground">
        Verdict Distribution
      </h3>
      <div className="h-64">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={pieData}
              cx="50%"
              cy="50%"
              innerRadius={50}
              outerRadius={80}
              paddingAngle={4}
              dataKey="value"
            >
              {pieData.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.color} />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{
                backgroundColor: "var(--popover)",
                border: "1px solid var(--border)",
                borderRadius: "8px",
                color: "var(--popover-foreground)",
              }}
              formatter={(value, name, props) => [
                `${value} (${props.payload.percentage}%)`,
                name,
              ]}
            />
            <Legend
              verticalAlign="bottom"
              height={36}
              formatter={(value) => (
                <span style={{ color: "var(--foreground)", fontSize: 12 }}>
                  {value}
                </span>
              )}
            />
          </PieChart>
        </ResponsiveContainer>
      </div>
    </motion.div>
  );
}

interface SeverityBreakdownChartProps {
  data: SeverityBreakdown[];
  loading?: boolean;
}

export function SeverityBreakdownChart({
  data,
  loading,
}: SeverityBreakdownChartProps) {
  if (loading) return <ChartSkeleton />;

  const barData = data.map((item) => ({
    name: item.severity.charAt(0).toUpperCase() + item.severity.slice(1),
    count: item.count,
    fill: severityColors[item.severity],
  }));

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: 0.2 }}
      className="rounded-xl border border-border bg-card p-5"
    >
      <h3 className="mb-4 text-sm font-semibold text-foreground">
        Vulnerability Severity
      </h3>
      <div className="h-64">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={barData} layout="vertical">
            <CartesianGrid
              strokeDasharray="3 3"
              stroke="var(--border)"
              horizontal={false}
            />
            <XAxis
              type="number"
              tick={{ fill: "var(--muted-foreground)", fontSize: 11 }}
              tickLine={false}
              axisLine={false}
            />
            <YAxis
              type="category"
              dataKey="name"
              tick={{ fill: "var(--muted-foreground)", fontSize: 11 }}
              tickLine={false}
              axisLine={false}
              width={60}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: "var(--popover)",
                border: "1px solid var(--border)",
                borderRadius: "8px",
                color: "var(--popover-foreground)",
              }}
            />
            <Bar dataKey="count" radius={[0, 4, 4, 0]}>
              {barData.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.fill} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </motion.div>
  );
}

interface ScannerMetricsChartProps {
  data: { name: string; avgTime: number; successRate: number }[];
  loading?: boolean;
}

export function ScannerMetricsChart({
  data,
  loading,
}: ScannerMetricsChartProps) {
  if (loading) return <ChartSkeleton />;

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: 0.3 }}
      className="rounded-xl border border-border bg-card p-5"
    >
      <h3 className="mb-4 text-sm font-semibold text-foreground">
        Scanner Performance
      </h3>
      <div className="h-64">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data}>
            <CartesianGrid
              strokeDasharray="3 3"
              stroke="var(--border)"
              vertical={false}
            />
            <XAxis
              dataKey="name"
              tick={{ fill: "var(--muted-foreground)", fontSize: 11 }}
              tickLine={false}
              axisLine={false}
            />
            <YAxis
              tick={{ fill: "var(--muted-foreground)", fontSize: 11 }}
              tickLine={false}
              axisLine={false}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: "var(--popover)",
                border: "1px solid var(--border)",
                borderRadius: "8px",
                color: "var(--popover-foreground)",
              }}
            />
            <Legend
              verticalAlign="top"
              height={36}
              formatter={(value) => (
                <span style={{ color: "var(--foreground)", fontSize: 12 }}>
                  {value === "avgTime" ? "Avg Time (s)" : "Success Rate (%)"}
                </span>
              )}
            />
            <Bar dataKey="avgTime" fill="#3b82f6" radius={[4, 4, 0, 0]} />
            <Bar dataKey="successRate" fill="#22c55e" radius={[4, 4, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </motion.div>
  );
}
