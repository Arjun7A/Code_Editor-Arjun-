import { Link } from "react-router-dom";
import { ExternalLink } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { TableRowSkeleton } from "@/components/ui/skeleton-loader";
import type { RecentPRRow } from "@/lib/types";
import { formatTimestamp, getToolBadgeStyle, TOOL_META } from "@/lib/scan-utils";

interface PRListProps {
  rows: RecentPRRow[];
  loading?: boolean;
}

function ToolCountBadge({
  label,
  tool,
  count,
}: {
  label: string;
  tool: string;
  count: number;
}) {
  return (
    <span
      className="inline-flex items-center rounded-full border px-2.5 py-1 text-xs font-medium"
      style={getToolBadgeStyle(tool)}
    >
      {label}: {count}
    </span>
  );
}

export function PRList({ rows, loading }: PRListProps) {
  return (
    <div className="overflow-hidden rounded-xl border border-border/60 bg-card/80">
      <div className="border-b border-border/60 px-5 py-4">
        <h2 className="text-lg font-semibold text-foreground">Recent Pull Requests</h2>
        <p className="mt-1 text-sm text-muted-foreground">
          Saved scan history from the dataset endpoint.
        </p>
      </div>

      <Table>
        <TableHeader>
          <TableRow className="border-border/60 hover:bg-transparent">
            <TableHead>PR URL</TableHead>
            <TableHead>Repository</TableHead>
            <TableHead>Total Issues</TableHead>
            <TableHead>Tool Counts</TableHead>
            <TableHead>Scan Timestamp</TableHead>
            <TableHead className="text-right">Details</TableHead>
          </TableRow>
        </TableHeader>

        <TableBody>
          {loading ? (
            Array.from({ length: 5 }).map((_, index) => (
              <TableRow key={index}>
                <TableCell colSpan={6} className="p-0">
                  <TableRowSkeleton />
                </TableCell>
              </TableRow>
            ))
          ) : rows.length === 0 ? (
            <TableRow>
              <TableCell colSpan={6} className="h-40 text-center text-muted-foreground">
                No PRs analyzed yet. Submit a PR to get started.
              </TableCell>
            </TableRow>
          ) : (
            rows.map((row) => (
              <TableRow key={row.id} className="border-border/60">
                <TableCell className="max-w-[360px]">
                  <a
                    href={row.prUrl}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-2 break-all text-sm text-primary hover:underline"
                  >
                    {row.prUrl}
                    <ExternalLink className="h-3.5 w-3.5 shrink-0" />
                  </a>
                </TableCell>

                <TableCell>
                  <div className="space-y-1">
                    <p className="font-medium text-foreground">{row.repoName}</p>
                    <p className="text-xs text-muted-foreground">{row.repoFullName}</p>
                  </div>
                </TableCell>

                <TableCell>
                  <Link
                    to={`/pr/${row.prId}`}
                    className="text-sm font-semibold text-primary hover:underline"
                  >
                    {row.totalIssues} issues
                  </Link>
                </TableCell>

                <TableCell>
                  <div className="flex flex-wrap gap-2">
                    <ToolCountBadge
                      label={TOOL_META.semgrep.label}
                      tool="semgrep"
                      count={row.scanSummary.semgrep}
                    />
                    <ToolCountBadge
                      label={TOOL_META["osv-scanner"].label}
                      tool="osv-scanner"
                      count={row.scanSummary.osv}
                    />
                    <ToolCountBadge
                      label={TOOL_META.gitleaks.label}
                      tool="gitleaks"
                      count={row.scanSummary.gitleaks}
                    />
                    <ToolCountBadge
                      label={TOOL_META.checkov.label}
                      tool="checkov"
                      count={row.scanSummary.checkov}
                    />
                  </div>
                </TableCell>

                <TableCell className="text-sm text-muted-foreground">
                  {formatTimestamp(row.scannedAt)}
                </TableCell>

                <TableCell className="text-right">
                  <Button asChild variant="outline" size="sm">
                    <Link to={`/pr/${row.prId}`}>View Details</Link>
                  </Button>
                </TableCell>
              </TableRow>
            ))
          )}
        </TableBody>
      </Table>
    </div>
  );
}
