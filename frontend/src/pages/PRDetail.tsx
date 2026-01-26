import { useState, useEffect } from "react";
import { Link, useParams } from "react-router-dom";
import { motion } from "framer-motion";
import {
  ArrowLeft,
  GitPullRequest,
  ExternalLink,
  FileText,
  Plus,
  Minus,
  Clock,
  User,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Header } from "@/components/layout/header";
import { VerdictBadge, RiskLevelBadge } from "@/components/ui/verdict-badge";
import { RiskGauge } from "@/components/ui/risk-gauge";
import { CodeDiffViewer } from "@/components/pr-detail/code-diff-viewer";
import { SecurityFindingsPanel } from "@/components/pr-detail/security-findings";
import { AIAnalysisSection } from "@/components/pr-detail/ai-analysis";
import { MLRiskBreakdown } from "@/components/pr-detail/ml-risk-breakdown";
import { ScannerResultsTable } from "@/components/pr-detail/scanner-results";
import { BlockchainVerificationPanel } from "@/components/pr-detail/blockchain-verification";
import { Skeleton } from "@/components/ui/skeleton-loader";
import { fetchPRAnalysis } from "@/lib/api";
import type { PRAnalysis } from "@/lib/types";

export default function PRDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [pr, setPR] = useState<PRAnalysis | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadPR() {
      if (!id) return;
      setLoading(true);
      try {
        const data = await fetchPRAnalysis(id);
        setPR(data);
      } catch (error) {
        console.error("[v0] Error loading PR:", error);
      } finally {
        setLoading(false);
      }
    }
    loadPR();
  }, [id]);

  if (loading) {
    return (
      <div className="min-h-screen bg-background">
        <Header />
        <main className="mx-auto max-w-screen-2xl px-4 py-6 lg:px-8">
          <PRDetailSkeleton />
        </main>
      </div>
    );
  }

  if (!pr) {
    return (
      <div className="min-h-screen bg-background">
        <Header />
        <main className="mx-auto max-w-screen-2xl px-4 py-6 lg:px-8">
          <div className="flex flex-col items-center justify-center py-20">
            <GitPullRequest className="h-12 w-12 text-muted-foreground" />
            <h1 className="mt-4 text-xl font-semibold text-foreground">
              PR Not Found
            </h1>
            <p className="mt-2 text-muted-foreground">
              The requested pull request could not be found.
            </p>
            <Button asChild className="mt-4">
              <Link to="/">Return to Dashboard</Link>
            </Button>
          </div>
        </main>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background">
      <Header />

      <main className="mx-auto max-w-screen-2xl px-4 py-6 lg:px-8">
        {/* Back Button */}
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          className="mb-6"
        >
          <Button asChild variant="ghost" className="gap-2">
            <Link to="/">
              <ArrowLeft className="h-4 w-4" />
              Back to Dashboard
            </Link>
          </Button>
        </motion.div>

        {/* PR Header */}
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          className="mb-8 rounded-xl border border-border bg-card p-6"
        >
          <div className="flex flex-col gap-6 lg:flex-row lg:items-start lg:justify-between">
            {/* Left Side - PR Info */}
            <div className="flex-1">
              <div className="flex items-start gap-4">
                <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-primary/10">
                  <GitPullRequest className="h-6 w-6 text-primary" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <h1 className="text-xl font-bold text-foreground">
                      {pr.title}
                    </h1>
                    {pr.verdict && <VerdictBadge verdict={pr.verdict} />}
                  </div>
                  <div className="mt-2 flex flex-wrap items-center gap-3 text-sm text-muted-foreground">
                    <span className="font-mono">
                      {pr.repository.fullName}#{pr.prNumber}
                    </span>
                    <span>|</span>
                    <div className="flex items-center gap-1">
                      <User className="h-4 w-4" />
                      {pr.author.username}
                    </div>
                    <span>|</span>
                    <div className="flex items-center gap-1">
                      <Clock className="h-4 w-4" />
                      {new Date(pr.createdAt).toLocaleDateString()}
                    </div>
                  </div>
                </div>
              </div>

              {/* Stats */}
              <div className="mt-4 flex flex-wrap items-center gap-4">
                <div className="flex items-center gap-2 rounded-lg bg-muted/30 px-3 py-1.5">
                  <FileText className="h-4 w-4 text-muted-foreground" />
                  <span className="text-sm font-medium text-foreground">
                    {pr.filesChanged} files
                  </span>
                </div>
                <div className="flex items-center gap-2 rounded-lg bg-success/10 px-3 py-1.5">
                  <Plus className="h-4 w-4 text-success" />
                  <span className="text-sm font-medium text-success">
                    {pr.additions} additions
                  </span>
                </div>
                <div className="flex items-center gap-2 rounded-lg bg-destructive/10 px-3 py-1.5">
                  <Minus className="h-4 w-4 text-destructive" />
                  <span className="text-sm font-medium text-destructive">
                    {pr.deletions} deletions
                  </span>
                </div>
                <RiskLevelBadge level={pr.riskLevel} />
              </div>

              {/* Author Info */}
              <div className="mt-4 flex items-center gap-3">
                <Avatar className="h-10 w-10 border border-border">
                  <AvatarImage src={pr.author.avatarUrl || "/placeholder.svg"} />
                  <AvatarFallback>
                    {pr.author.username.slice(0, 2).toUpperCase()}
                  </AvatarFallback>
                </Avatar>
                <div>
                  <p className="text-sm font-medium text-foreground">
                    {pr.author.username}
                  </p>
                  <p className="text-xs text-muted-foreground">
                    Reputation: {pr.author.reputation}/100
                  </p>
                </div>
                <Button variant="outline" size="sm" asChild className="ml-auto bg-transparent">
                  <a
                    href={`${pr.repository.url}/pull/${pr.prNumber}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-1"
                  >
                    View on GitHub
                    <ExternalLink className="h-3 w-3" />
                  </a>
                </Button>
              </div>
            </div>

            {/* Right Side - Risk Score */}
            <div className="flex flex-col items-center lg:items-end">
              <RiskGauge score={pr.riskScore} size="lg" />
            </div>
          </div>
        </motion.div>

        {/* Tabs Content */}
        <Tabs defaultValue="overview" className="space-y-6">
          <TabsList className="bg-muted/30">
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="security">Security Findings</TabsTrigger>
            <TabsTrigger value="ai">AI Analysis</TabsTrigger>
            <TabsTrigger value="code">Code Diff</TabsTrigger>
            <TabsTrigger value="blockchain">Blockchain</TabsTrigger>
          </TabsList>

          <TabsContent value="overview" className="space-y-6">
            <div className="grid gap-6 lg:grid-cols-2">
              <MLRiskBreakdown
                riskScore={pr.riskScore}
                factors={pr.mlRiskFactors}
              />
              <ScannerResultsTable results={pr.scannerResults} />
            </div>
            <div className="grid gap-6 lg:grid-cols-2">
              <SecurityFindingsPanel
                snykVulnerabilities={pr.snykVulnerabilities}
                semgrepFindings={pr.semgrepFindings}
              />
              <AIAnalysisSection findings={pr.aiFindings} />
            </div>
          </TabsContent>

          <TabsContent value="security">
            <div className="grid gap-6 lg:grid-cols-2">
              <SecurityFindingsPanel
                snykVulnerabilities={pr.snykVulnerabilities}
                semgrepFindings={pr.semgrepFindings}
              />
              <ScannerResultsTable results={pr.scannerResults} />
            </div>
          </TabsContent>

          <TabsContent value="ai">
            <div className="grid gap-6 lg:grid-cols-2">
              <AIAnalysisSection findings={pr.aiFindings} />
              <MLRiskBreakdown
                riskScore={pr.riskScore}
                factors={pr.mlRiskFactors}
              />
            </div>
          </TabsContent>

          <TabsContent value="code">
            <CodeDiffViewer diffs={pr.codeDiffs} />
          </TabsContent>

          <TabsContent value="blockchain">
            <div className="mx-auto max-w-2xl">
              <BlockchainVerificationPanel
                verification={pr.blockchainVerification}
              />
            </div>
          </TabsContent>
        </Tabs>
      </main>
    </div>
  );
}

function PRDetailSkeleton() {
  return (
    <div className="space-y-6">
      <Skeleton className="h-10 w-40" />
      <div className="rounded-xl border border-border bg-card p-6">
        <div className="flex gap-4">
          <Skeleton className="h-12 w-12 rounded-xl" />
          <div className="flex-1 space-y-2">
            <Skeleton className="h-6 w-96" />
            <Skeleton className="h-4 w-64" />
          </div>
          <Skeleton className="h-24 w-24 rounded-full" />
        </div>
      </div>
      <div className="grid gap-6 lg:grid-cols-2">
        <Skeleton className="h-96 rounded-xl" />
        <Skeleton className="h-96 rounded-xl" />
      </div>
    </div>
  );
}
