import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Download, ExternalLink, FileText, Search } from "lucide-react";
import { Header } from "@/components/layout/header";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { TableRowSkeleton } from "@/components/ui/skeleton-loader";
import { getDataset } from "@/lib/api";
import type { AuditLogEntry, ScanRiskLevel, ScanRecord, Verdict } from "@/lib/types";
import {
  formatTimestamp,
  getRepoName,
  getScanRiskLevel,
  getScanVerdict,
  getTotalIssues,
  hexToRgba,
  sortScans,
  toAuditLogEntry,
} from "@/lib/scan-utils";

const riskStyles: Record<ScanRiskLevel, string> = {
  low: "#3b82f6",
  medium: "#eab308",
  high: "#ef4444",
};

const verdictStyles: Record<Verdict, string> = {
  clean: "#22c55e",
  issues_found: "#eab308",
  critical: "#ef4444",
};

export default function AuditLogsPage() {
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [riskFilter, setRiskFilter] = useState<ScanRiskLevel | "all">("all");
  const [verdictFilter, setVerdictFilter] = useState<Verdict | "all">("all");

  useEffect(() => {
    void loadAuditLogs();
  }, []);

  async function loadAuditLogs() {
    setLoading(true);
    setError(null);

    try {
      const dataset = await getDataset();
      setScans(sortScans(dataset.scans));
    } catch (loadError) {
      const message =
        loadError instanceof Error
          ? loadError.message
          : "We couldn't load the audit log dataset.";
      setError(message);
      setScans([]);
    } finally {
      setLoading(false);
    }
  }

  const entries = useMemo(() => scans.map(toAuditLogEntry), [scans]);

  const filteredEntries = useMemo(() => {
    const normalizedSearch = search.trim().toLowerCase();

    return entries.filter((entry) => {
      if (riskFilter !== "all" && entry.riskLevel !== riskFilter) {
        return false;
      }

      if (verdictFilter !== "all" && entry.verdict !== verdictFilter) {
        return false;
      }

      if (!normalizedSearch) {
        return true;
      }

      return [
        entry.prNumber,
        entry.repository.toLowerCase(),
        entry.prUrl.toLowerCase(),
      ].some((value) => value.includes(normalizedSearch));
    });
  }, [entries, riskFilter, search, verdictFilter]);

  function exportAsJson() {
    downloadFile(
      JSON.stringify(scans, null, 2),
      `secureaudit-audit-logs-${new Date().toISOString().slice(0, 10)}.json`,
      "application/json"
    );
  }

  function exportAsCsv() {
    const header = [
      "PR ID",
      "Repository",
      "Verdict",
      "Risk Level",
      "Risk Score",
      "Timestamp",
      "PR URL",
    ];

    const rows = filteredEntries.map((entry) => [
      `#${entry.prNumber}`,
      entry.repository,
      getVerdictLabel(entry.verdict),
      entry.riskLevel.toUpperCase(),
      String(entry.riskScore),
      entry.timestamp,
      entry.prUrl,
    ]);

    const csv = [header, ...rows]
      .map((row) => row.map((value) => `"${String(value).replaceAll('"', '""')}"`).join(","))
      .join("\n");

    downloadFile(
      csv,
      `secureaudit-audit-logs-${new Date().toISOString().slice(0, 10)}.csv`,
      "text/csv"
    );
  }

  return (
    <div className="min-h-screen bg-background">
      <Header />

      <main className="mx-auto max-w-screen-2xl px-4 py-6 lg:px-8">
        <div className="mb-8">
          <h1 className="text-2xl font-bold tracking-tight text-foreground">
            Audit Logs
          </h1>
          <p className="mt-1 text-muted-foreground">
            Review every saved scan and jump into the full findings when needed.
          </p>
        </div>

        <div className="mb-6 flex flex-wrap items-center gap-3">
          <div className="relative min-w-[280px] flex-1">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              className="bg-secondary/30 pl-9"
              placeholder="Search by PR number, repository, or PR URL"
            />
          </div>

          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline">Risk Level</Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="start">
              <DropdownMenuItem onClick={() => setRiskFilter("all")}>
                All levels
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => setRiskFilter("high")}>
                HIGH
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => setRiskFilter("medium")}>
                MEDIUM
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => setRiskFilter("low")}>
                LOW
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>

          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline">Verdict</Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="start">
              <DropdownMenuItem onClick={() => setVerdictFilter("all")}>
                All verdicts
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => setVerdictFilter("clean")}>
                Clean
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => setVerdictFilter("issues_found")}>
                Issues Found
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => setVerdictFilter("critical")}>
                Critical
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>

          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button className="gap-2">
                <Download className="h-4 w-4" />
                Export
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem onClick={exportAsCsv}>
                <FileText className="mr-2 h-4 w-4" />
                Export CSV
              </DropdownMenuItem>
              <DropdownMenuItem onClick={exportAsJson}>
                <FileText className="mr-2 h-4 w-4" />
                Export JSON
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>

        {error ? (
          <div className="mb-6 rounded-xl border border-border/60 bg-card/70 p-4 text-sm text-muted-foreground">
            <p className="font-medium text-foreground">Backend offline</p>
            <p className="mt-1">{error}</p>
          </div>
        ) : null}

        <div className="overflow-hidden rounded-xl border border-border/60 bg-card/80">
          <Table>
            <TableHeader>
              <TableRow className="border-border/60 hover:bg-transparent">
                <TableHead>PR ID</TableHead>
                <TableHead>Repository</TableHead>
                <TableHead>Verdict</TableHead>
                <TableHead>Risk Level</TableHead>
                <TableHead>Risk Score</TableHead>
                <TableHead>Timestamp</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>

            <TableBody>
              {loading ? (
                Array.from({ length: 6 }).map((_, index) => (
                  <TableRow key={index}>
                    <TableCell colSpan={7} className="p-0">
                      <TableRowSkeleton />
                    </TableCell>
                  </TableRow>
                ))
              ) : filteredEntries.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="h-40 text-center text-muted-foreground">
                    No audit logs found.
                  </TableCell>
                </TableRow>
              ) : (
                filteredEntries.map((entry) => (
                  <TableRow key={entry.id} className="border-border/60">
                    <TableCell className="font-medium text-foreground">
                      #{entry.prNumber}
                    </TableCell>
                    <TableCell>
                      <div className="space-y-1">
                        <p className="font-medium text-foreground">{entry.repository}</p>
                        <a
                          href={entry.prUrl}
                          target="_blank"
                          rel="noreferrer"
                          className="inline-flex items-center gap-1 text-xs text-primary hover:underline"
                        >
                          View PR
                          <ExternalLink className="h-3 w-3" />
                        </a>
                      </div>
                    </TableCell>
                    <TableCell>
                      <StatusBadge
                        label={getVerdictLabel(entry.verdict)}
                        color={verdictStyles[entry.verdict]}
                      />
                    </TableCell>
                    <TableCell>
                      <StatusBadge
                        label={entry.riskLevel.toUpperCase()}
                        color={riskStyles[entry.riskLevel]}
                      />
                    </TableCell>
                    <TableCell className="font-medium text-foreground">
                      {entry.riskScore}
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {formatTimestamp(entry.timestamp)}
                    </TableCell>
                    <TableCell className="text-right">
                      <Button asChild variant="outline" size="sm">
                        <Link to={`/pr/${entry.prId}`}>View</Link>
                      </Button>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </div>
      </main>
    </div>
  );
}

function StatusBadge({ label, color }: { label: string; color: string }) {
  return (
    <Badge
      variant="outline"
      className="font-semibold"
      style={{
        color,
        backgroundColor: hexToRgba(color, 0.16),
        borderColor: hexToRgba(color, 0.35),
      }}
    >
      {label}
    </Badge>
  );
}

function getVerdictLabel(verdict: Verdict) {
  if (verdict === "clean") return "Clean";
  if (verdict === "critical") return "Critical";
  return "Issues Found";
}

function downloadFile(content: string, filename: string, type: string) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}
