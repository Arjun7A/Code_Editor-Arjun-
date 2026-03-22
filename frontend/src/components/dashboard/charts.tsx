"use client";

import type { ReactNode } from "react";
import { motion } from "framer-motion";
import {
  BarChart,
  Bar,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { ChartSkeleton } from "@/components/ui/skeleton-loader";
import type {
  ChartDataPoint,
  SeverityBreakdown,
  ToolMetric,
  VerdictDistribution,
} from "@/lib/types";

function EmptyState({ message }: { message: string }) {
  return (
    <div className="flex h-64 items-center justify-center text-center text-sm text-muted-foreground">
      {message}
    </div>
  );
}

function ChartShell({
  title,
  children,
  delay = 0,
}: {
  title: string;
  children: ReactNode;
  delay?: number;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay }}
      className="rounded-xl border border-border/60 bg-card/80 p-5"
    >
      <h3 className="mb-4 text-sm font-semibold text-foreground">{title}</h3>
      <div className="h-64">{children}</div>
    </motion.div>
  );
}

interface RiskTrendsChartProps {
  data: ChartDataPoint[];
  loading?: boolean;
}

export function RiskTrendsChart({ data, loading }: RiskTrendsChartProps) {
  if (loading) return <ChartSkeleton />;

  return (
    <ChartShell title="Risk Score Trends">
      {data.length === 0 ? (
        <EmptyState message="No scans yet. Submit a PR to build this chart." />
      ) : (
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data}>
            <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
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
            />
            <Tooltip
              contentStyle={{
                backgroundColor: "var(--popover)",
                border: "1px solid var(--border)",
                borderRadius: "8px",
                color: "var(--popover-foreground)",
              }}
              formatter={(value) => [`${value} issues`, "Total Issues"]}
            />
            <Bar dataKey="value" fill="#3b82f6" radius={[6, 6, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      )}
    </ChartShell>
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

  return (
    <ChartShell title="Verdict Distribution" delay={0.08}>
      {data.every((item) => item.count === 0) ? (
        <EmptyState message="No saved scans yet, so there’s nothing to distribute." />
      ) : (
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={data}
              dataKey="count"
              nameKey="label"
              innerRadius={58}
              outerRadius={86}
              paddingAngle={4}
            >
              {data.map((entry) => (
                <Cell key={entry.label} fill={entry.color} />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{
                backgroundColor: "var(--popover)",
                border: "1px solid var(--border)",
                borderRadius: "8px",
                color: "var(--popover-foreground)",
              }}
            />
          </PieChart>
        </ResponsiveContainer>
      )}
    </ChartShell>
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

  return (
    <ChartShell title="Vulnerability Severity" delay={0.16}>
      {data.every((item) => item.count === 0) ? (
        <EmptyState message="No findings yet. Severity totals will show up after the first scan." />
      ) : (
        <ResponsiveContainer width="100%" height="100%">
          <BarChart
            data={data.map((item) => ({
              name: item.severity.toUpperCase(),
              count: item.count,
              fill: item.color,
            }))}
          >
            <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
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
            <Bar dataKey="count" radius={[6, 6, 0, 0]}>
              {data.map((entry) => (
                <Cell key={entry.severity} fill={entry.color} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      )}
    </ChartShell>
  );
}

interface ScannerMetricsChartProps {
  data: ToolMetric[];
  loading?: boolean;
}

export function ScannerMetricsChart({
  data,
  loading,
}: ScannerMetricsChartProps) {
  if (loading) return <ChartSkeleton />;

  return (
    <ChartShell title="Scanner Performance" delay={0.24}>
      {data.every((item) => item.count === 0) ? (
        <EmptyState message="Tool totals will appear here after the first completed scan." />
      ) : (
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data}>
            <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
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
              formatter={(value) => [`${value} findings`, "Findings"]}
            />
            <Bar dataKey="count" radius={[6, 6, 0, 0]}>
              {data.map((entry) => (
                <Cell key={entry.name} fill={entry.color} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      )}
    </ChartShell>
  );
}
