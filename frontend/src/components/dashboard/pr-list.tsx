import { Link } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import {
  GitPullRequest,
  Clock,
  FileText,
  Plus,
  Minus,
  ExternalLink,
  LayoutGrid,
  List,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { VerdictBadge } from "@/components/ui/verdict-badge";
import { RiskGauge, RiskBar } from "@/components/ui/risk-gauge";
import { PRCardSkeleton, TableRowSkeleton } from "@/components/ui/skeleton-loader";
import type { PRAnalysis } from "@/lib/types";
import { cn } from "@/lib/utils";

interface PRListProps {
  prs: PRAnalysis[];
  loading?: boolean;
  viewMode?: "grid" | "table";
  onViewModeChange?: (mode: "grid" | "table") => void;
}

function formatTimeAgo(dateString: string): string {
  const date = new Date(dateString);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMs / 3600000);
  const diffDays = Math.floor(diffMs / 86400000);

  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  return `${diffDays}d ago`;
}

const listVariants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: {
      staggerChildren: 0.05,
    },
  },
};

const itemVariants = {
  hidden: { opacity: 0, y: 20 },
  visible: {
    opacity: 1,
    y: 0,
    transition: { duration: 0.3 },
  },
};

export function PRList({
  prs,
  loading,
  viewMode = "grid",
  onViewModeChange,
}: PRListProps) {
  if (loading) {
    return viewMode === "grid" ? (
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
        {Array.from({ length: 6 }).map((_, i) => (
          <PRCardSkeleton key={i} />
        ))}
      </div>
    ) : (
      <div className="rounded-xl border border-border bg-card">
        {Array.from({ length: 6 }).map((_, i) => (
          <TableRowSkeleton key={i} />
        ))}
      </div>
    );
  }

  return (
    <div>
      {/* View Mode Toggle */}
      <div className="mb-4 flex items-center justify-between">
        <h2 className="text-lg font-semibold text-foreground">
          Recent Pull Requests
        </h2>
        <div className="flex items-center gap-1 rounded-lg border border-border bg-muted/30 p-1">
          <Button
            variant="ghost"
            size="sm"
            className={cn(
              "h-8 px-3",
              viewMode === "grid" && "bg-background shadow-sm"
            )}
            onClick={() => onViewModeChange?.("grid")}
          >
            <LayoutGrid className="h-4 w-4" />
          </Button>
          <Button
            variant="ghost"
            size="sm"
            className={cn(
              "h-8 px-3",
              viewMode === "table" && "bg-background shadow-sm"
            )}
            onClick={() => onViewModeChange?.("table")}
          >
            <List className="h-4 w-4" />
          </Button>
        </div>
      </div>

      <AnimatePresence mode="wait">
        {viewMode === "grid" ? (
          <motion.div
            key="grid"
            variants={listVariants}
            initial="hidden"
            animate="visible"
            exit="hidden"
            className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3"
          >
            {prs.map((pr) => (
              <PRCard key={pr.id} pr={pr} />
            ))}
          </motion.div>
        ) : (
          <motion.div
            key="table"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
          >
            <PRTable prs={prs} />
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

function PRCard({ pr }: { pr: PRAnalysis }) {
  return (
    <motion.div
      variants={itemVariants}
      whileHover={{ scale: 1.02, transition: { duration: 0.2 } }}
      className="group relative overflow-hidden rounded-xl border border-border bg-card transition-all hover:border-primary/30 hover:shadow-lg hover:shadow-primary/5"
    >
      <Link to={`/pr/${pr.id}`} className="block p-5">
        {/* Glow effect */}
        <div className="pointer-events-none absolute inset-0 opacity-0 transition-opacity duration-300 group-hover:opacity-100">
          <div className="absolute -right-8 -top-8 h-32 w-32 rounded-full bg-primary/10 blur-3xl" />
        </div>

        <div className="relative">
          {/* Header */}
          <div className="flex items-start justify-between gap-3">
            <div className="flex items-center gap-3">
              <Avatar className="h-10 w-10 border border-border">
                <AvatarImage src={pr.author.avatarUrl || "/placeholder.svg"} />
                <AvatarFallback>
                  {pr.author.username.slice(0, 2).toUpperCase()}
                </AvatarFallback>
              </Avatar>
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium text-foreground">
                    {pr.repository.name}
                  </span>
                  <span className="text-sm text-muted-foreground">
                    #{pr.prNumber}
                  </span>
                </div>
                <span className="text-xs text-muted-foreground">
                  by {pr.author.username}
                </span>
              </div>
            </div>
            {pr.verdict && <VerdictBadge verdict={pr.verdict} size="sm" />}
          </div>

          {/* Title */}
          <p className="mt-3 line-clamp-2 text-sm text-foreground/90">
            {pr.title}
          </p>

          {/* Stats */}
          <div className="mt-4 flex items-center gap-4 text-xs text-muted-foreground">
            <div className="flex items-center gap-1">
              <FileText className="h-3.5 w-3.5" />
              {pr.filesChanged} files
            </div>
            <div className="flex items-center gap-1 text-success">
              <Plus className="h-3.5 w-3.5" />
              {pr.additions}
            </div>
            <div className="flex items-center gap-1 text-destructive">
              <Minus className="h-3.5 w-3.5" />
              {pr.deletions}
            </div>
          </div>

          {/* Footer */}
          <div className="mt-4 flex items-center justify-between">
            <div className="flex items-center gap-1 text-xs text-muted-foreground">
              <Clock className="h-3.5 w-3.5" />
              {formatTimeAgo(pr.createdAt)}
            </div>
            <RiskGauge score={pr.riskScore} size="sm" showLabel={false} />
          </div>
        </div>
      </Link>
    </motion.div>
  );
}

function PRTable({ prs }: { prs: PRAnalysis[] }) {
  return (
    <div className="overflow-hidden rounded-xl border border-border bg-card">
      <Table>
        <TableHeader>
          <TableRow className="border-border hover:bg-transparent">
            <TableHead className="text-muted-foreground">PR</TableHead>
            <TableHead className="text-muted-foreground">Repository</TableHead>
            <TableHead className="text-muted-foreground">Author</TableHead>
            <TableHead className="text-muted-foreground">Risk</TableHead>
            <TableHead className="text-muted-foreground">Verdict</TableHead>
            <TableHead className="text-muted-foreground">Changes</TableHead>
            <TableHead className="text-right text-muted-foreground">
              Time
            </TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {prs.map((pr) => (
            <TableRow
              key={pr.id}
              className="group cursor-pointer border-border transition-colors hover:bg-muted/30"
            >
              <TableCell>
                <Link
                  to={`/pr/${pr.id}`}
                  className="flex items-center gap-2 font-medium text-foreground"
                >
                  <GitPullRequest className="h-4 w-4 text-primary" />
                  #{pr.prNumber}
                  <ExternalLink className="h-3 w-3 text-muted-foreground opacity-0 transition-opacity group-hover:opacity-100" />
                </Link>
              </TableCell>
              <TableCell>
                <span className="text-sm text-foreground">
                  {pr.repository.name}
                </span>
              </TableCell>
              <TableCell>
                <div className="flex items-center gap-2">
                  <Avatar className="h-6 w-6">
                    <AvatarImage src={pr.author.avatarUrl || "/placeholder.svg"} />
                    <AvatarFallback className="text-xs">
                      {pr.author.username.slice(0, 2).toUpperCase()}
                    </AvatarFallback>
                  </Avatar>
                  <span className="text-sm text-muted-foreground">
                    {pr.author.username}
                  </span>
                </div>
              </TableCell>
              <TableCell>
                <div className="flex items-center gap-2">
                  <RiskBar
                    score={pr.riskScore}
                    showLabel={false}
                    className="w-16"
                  />
                  <span className="text-sm font-medium text-foreground">
                    {pr.riskScore}
                  </span>
                </div>
              </TableCell>
              <TableCell>
                {pr.verdict && (
                  <VerdictBadge verdict={pr.verdict} size="sm" animated={false} />
                )}
              </TableCell>
              <TableCell>
                <div className="flex items-center gap-2 text-xs">
                  <span className="text-muted-foreground">
                    {pr.filesChanged}f
                  </span>
                  <span className="text-success">+{pr.additions}</span>
                  <span className="text-destructive">-{pr.deletions}</span>
                </div>
              </TableCell>
              <TableCell className="text-right text-sm text-muted-foreground">
                {formatTimeAgo(pr.createdAt)}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}
