import { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import {
  History,
  Search,
  Filter,
  Download,
  ChevronDown,
  ArrowUpDown,
  ExternalLink,
  CheckCircle2,
  Clock,
  XCircle,
  Link2,
  FileText,
  X,
} from "lucide-react";
import { Header } from "@/components/layout/header";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Calendar } from "@/components/ui/calendar";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import { Badge } from "@/components/ui/badge";
import { VerdictBadge, RiskLevelBadge } from "@/components/ui/verdict-badge";
import { RiskBar } from "@/components/ui/risk-gauge";
import { TableRowSkeleton } from "@/components/ui/skeleton-loader";
import { fetchAuditLogs, verifyBlockchainRecord } from "@/lib/api";
import type { AuditLogEntry, FilterOptions, Verdict, RiskLevel } from "@/lib/types";
import { cn } from "@/lib/utils";

type SortKey = "prNumber" | "timestamp" | "riskScore";
type SortOrder = "asc" | "desc";

export default function AuditLogsPage() {
  const [logs, setLogs] = useState<AuditLogEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [filters, setFilters] = useState<FilterOptions>({
    verdict: "all",
    riskLevel: "all",
    search: "",
  });
  const [sortKey, setSortKey] = useState<SortKey>("timestamp");
  const [sortOrder, setSortOrder] = useState<SortOrder>("desc");
  const [dateRange, setDateRange] = useState<{ from?: Date; to?: Date }>({});
  const [verifyDialogOpen, setVerifyDialogOpen] = useState(false);
  const [verifyPrId, setVerifyPrId] = useState("");
  const [verifyResult, setVerifyResult] = useState<{
    verified: boolean;
    hash: string;
    timestamp: string;
  } | null>(null);
  const [verifying, setVerifying] = useState(false);

  useEffect(() => {
    async function loadLogs() {
      setLoading(true);
      try {
        const data = await fetchAuditLogs(filters);
        setLogs(data);
      } catch (error) {
        console.error("[v0] Error loading audit logs:", error);
      } finally {
        setLoading(false);
      }
    }
    loadLogs();
  }, [filters]);

  const handleSort = (key: SortKey) => {
    if (sortKey === key) {
      setSortOrder(sortOrder === "asc" ? "desc" : "asc");
    } else {
      setSortKey(key);
      setSortOrder("desc");
    }
  };

  const sortedLogs = [...logs].sort((a, b) => {
    let comparison = 0;
    switch (sortKey) {
      case "prNumber":
        comparison = a.prNumber - b.prNumber;
        break;
      case "timestamp":
        comparison =
          new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime();
        break;
      case "riskScore":
        comparison = a.riskScore - b.riskScore;
        break;
    }
    return sortOrder === "asc" ? comparison : -comparison;
  });

  const handleVerify = async () => {
    if (!verifyPrId) return;
    setVerifying(true);
    try {
      const result = await verifyBlockchainRecord(verifyPrId);
      setVerifyResult(result);
    } catch (error) {
      console.error("[v0] Error verifying:", error);
    } finally {
      setVerifying(false);
    }
  };

  const exportCSV = () => {
    const headers = [
      "PR ID",
      "Repository",
      "Verdict",
      "Risk Level",
      "Risk Score",
      "Timestamp",
      "Blockchain Status",
    ];
    const rows = logs.map((log) => [
      log.prNumber,
      log.repository.fullName,
      log.verdict,
      log.riskLevel,
      log.riskScore,
      log.timestamp,
      log.blockchainStatus,
    ]);
    const csv = [headers, ...rows].map((row) => row.join(",")).join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `audit-logs-${new Date().toISOString().split("T")[0]}.csv`;
    a.click();
  };

  const activeFiltersCount =
    (filters.verdict && filters.verdict !== "all" ? 1 : 0) +
    (filters.riskLevel && filters.riskLevel !== "all" ? 1 : 0) +
    (dateRange.from ? 1 : 0);

  return (
    <div className="min-h-screen bg-background">
      <Header />

      <main className="mx-auto max-w-screen-2xl px-4 py-6 lg:px-8">
        {/* Page Header */}
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          className="mb-8"
        >
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-primary/10">
              <History className="h-5 w-5 text-primary" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-foreground">
                Audit Logs
              </h1>
              <p className="text-muted-foreground">
                Historical records of all PR security analyses
              </p>
            </div>
          </div>
        </motion.div>

        {/* Filters & Actions */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="mb-6 space-y-4"
        >
          <div className="flex flex-wrap items-center gap-3">
            {/* Search */}
            <div className="relative flex-1 min-w-50">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                placeholder="Search by PR ID, repository..."
                value={filters.search || ""}
                onChange={(e) =>
                  setFilters({ ...filters, search: e.target.value })
                }
                className="h-10 bg-secondary/30 pl-9"
              />
            </div>

            {/* Verdict Filter */}
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" className="h-10 gap-2 bg-secondary/30">
                  <Filter className="h-4 w-4" />
                  Verdict
                  <ChevronDown className="h-4 w-4" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="start">
                <DropdownMenuLabel>Filter by Verdict</DropdownMenuLabel>
                <DropdownMenuSeparator />
                {(["all", "approved", "blocked", "manual_review"] as const).map(
                  (v) => (
                    <DropdownMenuItem
                      key={v}
                      onClick={() =>
                        setFilters({ ...filters, verdict: v as Verdict | "all" })
                      }
                      className={cn(filters.verdict === v && "bg-accent")}
                    >
                      {v === "all"
                        ? "All Verdicts"
                        : v === "manual_review"
                          ? "Manual Review"
                          : v.charAt(0).toUpperCase() + v.slice(1)}
                    </DropdownMenuItem>
                  )
                )}
              </DropdownMenuContent>
            </DropdownMenu>

            {/* Risk Level Filter */}
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" className="h-10 gap-2 bg-secondary/30">
                  Risk Level
                  <ChevronDown className="h-4 w-4" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="start">
                <DropdownMenuLabel>Filter by Risk</DropdownMenuLabel>
                <DropdownMenuSeparator />
                {(["all", "critical", "high", "medium", "low"] as const).map(
                  (level) => (
                    <DropdownMenuItem
                      key={level}
                      onClick={() =>
                        setFilters({
                          ...filters,
                          riskLevel: level as RiskLevel | "all",
                        })
                      }
                      className={cn(filters.riskLevel === level && "bg-accent")}
                    >
                      {level === "all"
                        ? "All Levels"
                        : level.charAt(0).toUpperCase() + level.slice(1)}
                    </DropdownMenuItem>
                  )
                )}
              </DropdownMenuContent>
            </DropdownMenu>

            {/* Date Range */}
            <Popover>
              <PopoverTrigger asChild>
                <Button variant="outline" className="h-10 gap-2 bg-secondary/30">
                  <Clock className="h-4 w-4" />
                  Date Range
                  <ChevronDown className="h-4 w-4" />
                </Button>
              </PopoverTrigger>
              <PopoverContent className="w-auto p-0" align="start">
                <Calendar
                  mode="range"
                  selected={{ from: dateRange.from, to: dateRange.to }}
                  onSelect={(range) =>
                    setDateRange({ from: range?.from, to: range?.to })
                  }
                  numberOfMonths={2}
                />
              </PopoverContent>
            </Popover>

            {/* Clear Filters */}
            {activeFiltersCount > 0 && (
              <Button
                variant="ghost"
                size="sm"
                onClick={() => {
                  setFilters({
                    verdict: "all",
                    riskLevel: "all",
                    search: "",
                  });
                  setDateRange({});
                }}
                className="h-10 gap-1 text-muted-foreground"
              >
                <X className="h-4 w-4" />
                Clear
              </Button>
            )}

            <div className="flex-1" />

            {/* Verify Button */}
            <Dialog open={verifyDialogOpen} onOpenChange={setVerifyDialogOpen}>
              <DialogTrigger asChild>
                <Button variant="outline" className="h-10 gap-2 bg-transparent">
                  <Link2 className="h-4 w-4" />
                  Verify Record
                </Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>Verify Blockchain Record</DialogTitle>
                  <DialogDescription>
                    Enter a PR ID to verify its audit record on the blockchain.
                  </DialogDescription>
                </DialogHeader>
                <div className="space-y-4 py-4">
                  <Input
                    placeholder="Enter PR ID (e.g., pr-1)"
                    value={verifyPrId}
                    onChange={(e) => setVerifyPrId(e.target.value)}
                  />
                  <Button
                    onClick={handleVerify}
                    disabled={!verifyPrId || verifying}
                    className="w-full"
                  >
                    {verifying ? "Verifying..." : "Verify on Blockchain"}
                  </Button>

                  {verifyResult && (
                    <motion.div
                      initial={{ opacity: 0, y: 10 }}
                      animate={{ opacity: 1, y: 0 }}
                      className={cn(
                        "rounded-lg p-4",
                        verifyResult.verified
                          ? "bg-success/10"
                          : "bg-destructive/10"
                      )}
                    >
                      <div className="flex items-center gap-2">
                        {verifyResult.verified ? (
                          <CheckCircle2 className="h-5 w-5 text-success" />
                        ) : (
                          <XCircle className="h-5 w-5 text-destructive" />
                        )}
                        <span
                          className={cn(
                            "font-semibold",
                            verifyResult.verified
                              ? "text-success"
                              : "text-destructive"
                          )}
                        >
                          {verifyResult.verified
                            ? "Record Verified"
                            : "Verification Failed"}
                        </span>
                      </div>
                      {verifyResult.verified && (
                        <div className="mt-3 space-y-2 text-sm">
                          <p className="text-muted-foreground">
                            <span className="font-medium text-foreground">
                              Hash:{" "}
                            </span>
                            <code className="text-xs">
                              {verifyResult.hash.slice(0, 20)}...
                            </code>
                          </p>
                          <p className="text-muted-foreground">
                            <span className="font-medium text-foreground">
                              Timestamp:{" "}
                            </span>
                            {new Date(verifyResult.timestamp).toLocaleString()}
                          </p>
                        </div>
                      )}
                    </motion.div>
                  )}
                </div>
              </DialogContent>
            </Dialog>

            {/* Export */}
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button className="h-10 gap-2">
                  <Download className="h-4 w-4" />
                  Export
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem onClick={exportCSV}>
                  <FileText className="mr-2 h-4 w-4" />
                  Export as CSV
                </DropdownMenuItem>
                <DropdownMenuItem>
                  <FileText className="mr-2 h-4 w-4" />
                  Export as PDF
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>

          {/* Active Filters */}
          <AnimatePresence>
            {activeFiltersCount > 0 && (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: "auto" }}
                exit={{ opacity: 0, height: 0 }}
                className="flex flex-wrap items-center gap-2"
              >
                <span className="text-sm text-muted-foreground">
                  Active filters:
                </span>
                {filters.verdict && filters.verdict !== "all" && (
                  <Badge
                    variant="secondary"
                    className="gap-1 bg-primary/10 text-primary"
                  >
                    Verdict: {filters.verdict.replace("_", " ")}
                    <button
                      type="button"
                      onClick={() =>
                        setFilters({ ...filters, verdict: "all" })
                      }
                    >
                      <X className="h-3 w-3" />
                    </button>
                  </Badge>
                )}
                {filters.riskLevel && filters.riskLevel !== "all" && (
                  <Badge
                    variant="secondary"
                    className="gap-1 bg-primary/10 text-primary"
                  >
                    Risk: {filters.riskLevel}
                    <button
                      type="button"
                      onClick={() =>
                        setFilters({ ...filters, riskLevel: "all" })
                      }
                    >
                      <X className="h-3 w-3" />
                    </button>
                  </Badge>
                )}
                {dateRange.from && (
                  <Badge
                    variant="secondary"
                    className="gap-1 bg-primary/10 text-primary"
                  >
                    Date range
                    <button type="button" onClick={() => setDateRange({})}>
                      <X className="h-3 w-3" />
                    </button>
                  </Badge>
                )}
              </motion.div>
            )}
          </AnimatePresence>
        </motion.div>

        {/* Table */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="overflow-hidden rounded-xl border border-border bg-card"
        >
          <Table>
            <TableHeader>
              <TableRow className="border-border hover:bg-transparent">
                <TableHead
                  className="cursor-pointer text-muted-foreground"
                  onClick={() => handleSort("prNumber")}
                >
                  <div className="flex items-center gap-1">
                    PR ID
                    <ArrowUpDown className="h-3 w-3" />
                  </div>
                </TableHead>
                <TableHead className="text-muted-foreground">
                  Repository
                </TableHead>
                <TableHead className="text-muted-foreground">Verdict</TableHead>
                <TableHead className="text-muted-foreground">
                  Risk Level
                </TableHead>
                <TableHead
                  className="cursor-pointer text-muted-foreground"
                  onClick={() => handleSort("riskScore")}
                >
                  <div className="flex items-center gap-1">
                    Risk Score
                    <ArrowUpDown className="h-3 w-3" />
                  </div>
                </TableHead>
                <TableHead
                  className="cursor-pointer text-muted-foreground"
                  onClick={() => handleSort("timestamp")}
                >
                  <div className="flex items-center gap-1">
                    Timestamp
                    <ArrowUpDown className="h-3 w-3" />
                  </div>
                </TableHead>
                <TableHead className="text-muted-foreground">
                  Blockchain
                </TableHead>
                <TableHead className="text-right text-muted-foreground">
                  Actions
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading ? (
                Array.from({ length: 10 }).map((_, i) => (
                  <TableRow key={i}>
                    <TableCell colSpan={8} className="p-0">
                      <TableRowSkeleton />
                    </TableCell>
                  </TableRow>
                ))
              ) : sortedLogs.length === 0 ? (
                <TableRow>
                  <TableCell
                    colSpan={8}
                    className="h-40 text-center text-muted-foreground"
                  >
                    No audit logs found
                  </TableCell>
                </TableRow>
              ) : (
                sortedLogs.map((log, index) => (
                  <motion.tr
                    key={log.id}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: index * 0.02 }}
                    className="border-border transition-colors hover:bg-muted/30"
                  >
                    <TableCell>
                      <Link
                        to={`/pr/${log.prId}`}
                        className="flex items-center gap-2 font-mono text-sm font-medium text-foreground hover:text-primary"
                      >
                        #{log.prNumber}
                      </Link>
                    </TableCell>
                    <TableCell className="text-sm text-foreground">
                      {log.repository.name}
                    </TableCell>
                    <TableCell>
                      <VerdictBadge
                        verdict={log.verdict}
                        size="sm"
                        animated={false}
                      />
                    </TableCell>
                    <TableCell>
                      <RiskLevelBadge level={log.riskLevel} size="sm" />
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <RiskBar
                          score={log.riskScore}
                          showLabel={false}
                          className="w-16"
                        />
                        <span className="text-sm font-medium text-foreground">
                          {log.riskScore}
                        </span>
                      </div>
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">
                      {new Date(log.timestamp).toLocaleString()}
                    </TableCell>
                    <TableCell>
                      <BlockchainStatusBadge status={log.blockchainStatus} />
                    </TableCell>
                    <TableCell className="text-right">
                      <Button asChild variant="ghost" size="sm">
                        <Link to={`/pr/${log.prId}`}>
                          <ExternalLink className="h-4 w-4" />
                        </Link>
                      </Button>
                    </TableCell>
                  </motion.tr>
                ))
              )}
            </TableBody>
          </Table>
        </motion.div>

        {/* Pagination Info */}
        <div className="mt-4 flex items-center justify-between text-sm text-muted-foreground">
          <span>Showing {sortedLogs.length} records</span>
          <span>Total: {logs.length} audit entries</span>
        </div>
      </main>
    </div>
  );
}

function BlockchainStatusBadge({
  status,
}: {
  status: "verified" | "pending" | "failed";
}) {
  const config = {
    verified: {
      icon: CheckCircle2,
      label: "Verified",
      className: "bg-success/10 text-success border-success/30",
    },
    pending: {
      icon: Clock,
      label: "Pending",
      className: "bg-warning/10 text-warning border-warning/30",
    },
    failed: {
      icon: XCircle,
      label: "Failed",
      className: "bg-destructive/10 text-destructive border-destructive/30",
    },
  };

  const { icon: Icon, label, className } = config[status];

  return (
    <Badge variant="outline" className={cn("gap-1", className)}>
      <Icon className="h-3 w-3" />
      {label}
    </Badge>
  );
}
