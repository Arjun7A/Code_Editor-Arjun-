"use client";

import { motion } from "framer-motion";
import {
  CheckCircle2,
  XCircle,
  MinusCircle,
  Clock,
  Activity,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { cn } from "@/lib/utils";
import type { ScannerResult } from "@/lib/types";

interface ScannerResultsTableProps {
  results: ScannerResult[];
}

const statusConfig = {
  success: {
    icon: CheckCircle2,
    label: "Completed",
    color: "text-success",
    bgColor: "bg-success/10",
  },
  failed: {
    icon: XCircle,
    label: "Failed",
    color: "text-destructive",
    bgColor: "bg-destructive/10",
  },
  skipped: {
    icon: MinusCircle,
    label: "Skipped",
    color: "text-muted-foreground",
    bgColor: "bg-muted/30",
  },
};

export function ScannerResultsTable({ results }: ScannerResultsTableProps) {
  const totalTime = results.reduce((sum, r) => sum + r.executionTime, 0);
  const totalIssues = results.reduce((sum, r) => sum + r.issuesFound, 0);

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="rounded-xl border border-border bg-card"
    >
      {/* Header */}
      <div className="flex items-center gap-3 border-b border-border px-4 py-3">
        <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-accent/10">
          <Activity className="h-4 w-4 text-accent" />
        </div>
        <div className="flex-1">
          <h3 className="font-semibold text-foreground">Scanner Results</h3>
          <p className="text-xs text-muted-foreground">
            {results.length} scanners executed in {totalTime.toFixed(1)}s
          </p>
        </div>
        <Badge
          variant="outline"
          className={cn(
            totalIssues > 0
              ? "border-warning/30 bg-warning/10 text-warning"
              : "border-success/30 bg-success/10 text-success"
          )}
        >
          {totalIssues} issues
        </Badge>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <Table>
          <TableHeader>
            <TableRow className="border-border hover:bg-transparent">
              <TableHead className="text-muted-foreground">Scanner</TableHead>
              <TableHead className="text-muted-foreground">Status</TableHead>
              <TableHead className="text-muted-foreground">Issues</TableHead>
              <TableHead className="text-muted-foreground">Severity</TableHead>
              <TableHead className="text-right text-muted-foreground">
                Time
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {results.map((result, index) => {
              const status = statusConfig[result.status];
              const StatusIcon = status.icon;

              return (
                <motion.tr
                  key={result.id}
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: index * 0.1 }}
                  className="border-border transition-colors hover:bg-muted/30"
                >
                  <TableCell>
                    <span className="font-medium text-foreground">
                      {result.name}
                    </span>
                  </TableCell>
                  <TableCell>
                    <div
                      className={cn(
                        "inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium",
                        status.bgColor,
                        status.color
                      )}
                    >
                      <StatusIcon className="h-3 w-3" />
                      {status.label}
                    </div>
                  </TableCell>
                  <TableCell>
                    <span
                      className={cn(
                        "font-medium",
                        result.issuesFound > 0
                          ? "text-warning"
                          : "text-muted-foreground"
                      )}
                    >
                      {result.issuesFound}
                    </span>
                  </TableCell>
                  <TableCell>
                    <SeverityPills severity={result.severity} />
                  </TableCell>
                  <TableCell className="text-right">
                    <div className="flex items-center justify-end gap-1 text-muted-foreground">
                      <Clock className="h-3 w-3" />
                      <span className="text-sm">{result.executionTime}s</span>
                    </div>
                  </TableCell>
                </motion.tr>
              );
            })}
          </TableBody>
        </Table>
      </div>
    </motion.div>
  );
}

function SeverityPills({
  severity,
}: {
  severity: { critical: number; high: number; medium: number; low: number };
}) {
  return (
    <div className="flex items-center gap-1">
      {severity.critical > 0 && (
        <span className="inline-flex h-5 min-w-5 items-center justify-center rounded bg-critical/20 px-1.5 text-xs font-medium text-critical">
          {severity.critical}
        </span>
      )}
      {severity.high > 0 && (
        <span className="inline-flex h-5 min-w-5 items-center justify-center rounded bg-destructive/20 px-1.5 text-xs font-medium text-destructive">
          {severity.high}
        </span>
      )}
      {severity.medium > 0 && (
        <span className="inline-flex h-5 min-w-5 items-center justify-center rounded bg-warning/20 px-1.5 text-xs font-medium text-warning">
          {severity.medium}
        </span>
      )}
      {severity.low > 0 && (
        <span className="inline-flex h-5 min-w-5 items-center justify-center rounded bg-success/20 px-1.5 text-xs font-medium text-success">
          {severity.low}
        </span>
      )}
      {severity.critical === 0 &&
        severity.high === 0 &&
        severity.medium === 0 &&
        severity.low === 0 && (
          <span className="text-xs text-muted-foreground">-</span>
        )}
    </div>
  );
}
