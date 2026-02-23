import React from "react";
import { useState } from "react";
import { Header } from "@/components/layout/header";
import { Sidebar } from "@/components/layout/sidebar";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
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
import { Switch } from "@/components/ui/switch";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { useToast } from "@/hooks/use-toast";
import {
  GitPullRequest,
  Link,
  Upload,
  Shield,
  Brain,
  FileCode,
  AlertTriangle,
  CheckCircle2,
  Loader2,
  Github,
  GitBranch,
  Code2,
  Sparkles,
  Zap,
  Lock,
  ScanLine,
  ExternalLink,
  BarChart3,
  ChevronDown,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { analyzeGitHubAndMap, scanCode } from "@/lib/api";

type AnalysisStep = {
  id: string;
  label: string;
  status: "pending" | "running" | "complete" | "error";
  icon: React.ReactNode;
};

export default function SubmitPRPage() {
  const { toast } = useToast();
  const [submissionMethod, setSubmissionMethod] = useState<"url" | "manual">(
    "url"
  );
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisProgress, setAnalysisProgress] = useState(0);
  const [currentStep, setCurrentStep] = useState(0);
  const [expandedPR, setExpandedPR] = useState<number | null>(null);

  const [formData, setFormData] = useState({
    prUrl: "",
    repository: "",
    branch: "",
    title: "",
    description: "",
    diffContent: "",
    enableAI: true,
    enableML: true,
    enableSecurityScan: true,
    priority: "normal",
    notifyOnComplete: true,
  });

  // Store real ML analysis results
  const [analysisResults, setAnalysisResults] = useState<any>(null);
  // Store real scanner results (Snyk + Semgrep)
  const [scanResults, setScanResults] = useState<any>(null);

  const analysisSteps: AnalysisStep[] = [
    {
      id: "fetch",
      label: "Fetching PR Data from GitHub",
      status:
        currentStep > 0 ? "complete" : currentStep === 0 ? "running" : "pending",
      icon: <GitPullRequest className="h-4 w-4" />,
    },
    {
      id: "scan",
      label: "Security Scanning",
      status:
        currentStep > 1 ? "complete" : currentStep === 1 ? "running" : "pending",
      icon: <ScanLine className="h-4 w-4" />,
    },
    {
      id: "ai",
      label: "AI Analysis",
      status:
        currentStep > 2 ? "complete" : currentStep === 2 ? "running" : "pending",
      icon: <Brain className="h-4 w-4" />,
    },
    {
      id: "ml",
      label: "ML Risk Assessment (XGBoost)",
      status:
        currentStep > 3 ? "complete" : currentStep === 3 ? "running" : "pending",
      icon: <Sparkles className="h-4 w-4" />,
    },
    {
      id: "blockchain",
      label: "Blockchain Verification",
      status:
        currentStep > 4 ? "complete" : currentStep === 4 ? "running" : "pending",
      icon: <Lock className="h-4 w-4" />,
    },
  ];

  // Parse repo from a GitHub URL or owner/repo format
  const parseRepo = (input: string): string | null => {
    // Handle "owner/repo" format directly
    if (/^[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+$/.test(input.trim())) {
      return input.trim();
    }
    // Handle full GitHub URLs: https://github.com/owner/repo/...
    const match = input.match(/github\.com\/([^/]+\/[^/]+)/);
    return match ? match[1].replace(/\.git$/, "") : null;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    const repoInput = submissionMethod === "url" ? formData.prUrl : formData.repository;

    if (!repoInput) {
      toast({
        title: "Error",
        description: "Please enter a GitHub repository URL or owner/repo",
        variant: "destructive",
      });
      return;
    }

    const repo = parseRepo(repoInput);
    if (!repo) {
      toast({
        title: "Invalid Format",
        description: "Please enter a valid GitHub URL (e.g., https://github.com/facebook/react) or owner/repo format (e.g., facebook/react)",
        variant: "destructive",
      });
      return;
    }

    setIsAnalyzing(true);
    setAnalysisProgress(0);
    setCurrentStep(0);
    setAnalysisResults(null);
    setScanResults(null);

    try {
      // Step 0: Fetching PR data (visual)
      setCurrentStep(0);
      setAnalysisProgress(10);
      await new Promise((r) => setTimeout(r, 400));

      // Step 1: Security Scanning — await it first
      setCurrentStep(1);
      setAnalysisProgress(25);
      let scanResult: PromiseSettledResult<Awaited<ReturnType<typeof scanCode>>>;
      try {
        const scanData = await scanCode({ repoUrl: repo });
        scanResult = { status: "fulfilled", value: scanData };
        setScanResults(scanData);
      } catch (scanErr: any) {
        console.warn("[Scanner] Scan failed:", scanErr?.message);
        scanResult = { status: "rejected", reason: scanErr };
        setScanResults(null);
      }
      await new Promise((r) => setTimeout(r, 300));

      // Step 2: AI Analysis (visual — embedded inside analyze_github)
      setCurrentStep(2);
      setAnalysisProgress(50);
      await new Promise((r) => setTimeout(r, 400));

      // Step 3: ML Risk Assessment
      setCurrentStep(3);
      setAnalysisProgress(65);
      const mlData = await analyzeGitHubAndMap(repo, 10);
      const results = mlData.raw;
      setAnalysisResults(results);

      // Step 4: Blockchain / complete
      setCurrentStep(4);
      setAnalysisProgress(88);
      await new Promise((r) => setTimeout(r, 500));

      setCurrentStep(5);
      setAnalysisProgress(100);

      const highCount = results?.high_risk_count ?? 0;
      const totalCount = results?.total_prs_analyzed ?? 0;
      const scanIssues = scanResult.status === "fulfilled"
        ? ((scanResult.value.summary as any)?.total_issues ?? 0)
        : 0;

      toast({
        title: "✅ Analysis Complete",
        description: `Analyzed ${totalCount} PRs — ${highCount} high risk, ${scanIssues} security issues`,
        variant: (highCount > 0 || scanIssues > 0) ? "destructive" : "default",
      });
    } catch (err: any) {
      const msg = err?.message || "Failed to connect to analysis API";
      setCurrentStep(-1);
      setAnalysisProgress(0);
      setIsAnalyzing(false);

      toast({
        title: "Analysis Failed",
        description: msg,
        variant: "destructive",
      });
    }
  };

  return (
    <div className="flex h-screen bg-background">
      <Sidebar />

      <div className="flex flex-1 flex-col overflow-hidden">
        <Header />

        <main className="flex-1 overflow-y-auto p-6">
          <div className="mx-auto max-w-4xl">
            {/* Header */}
            <div className="mb-8">
              <h1 className="text-3xl font-bold text-foreground">
                Submit PR for Analysis
              </h1>
              <p className="mt-2 text-muted-foreground">
                Submit a pull request for comprehensive security analysis,
                AI-powered code review, and ML risk assessment.
              </p>
            </div>

            {isAnalyzing || analysisResults ? (
              <div className="space-y-6">
                <Card className="border-border/50 bg-card/50 backdrop-blur-sm">
                  <CardHeader className="text-center">
                    <div className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-primary/10">
                      {analysisResults ? (
                        <CheckCircle2 className="h-8 w-8 text-success" />
                      ) : (
                        <Shield className="h-8 w-8 animate-pulse text-primary" />
                      )}
                    </div>
                    <CardTitle className="text-2xl">
                      {analysisResults ? "Analysis Complete" : "Analyzing PR"}
                    </CardTitle>
                    <CardDescription>
                      {analysisResults
                        ? `Analyzed ${analysisResults.total_prs_analyzed} PRs from ${analysisResults.repo}`
                        : "Please wait while we perform comprehensive security analysis"}
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-8">
                    <div className="space-y-2">
                      <div className="flex items-center justify-between text-sm">
                        <span className="text-muted-foreground">
                          Overall Progress
                        </span>
                        <span className="font-mono text-foreground">
                          {Math.round(analysisProgress)}%
                        </span>
                      </div>
                      <Progress value={analysisProgress} className="h-2" />
                    </div>

                    <div className="space-y-4">
                      {analysisSteps.map((step, index) => (
                        <div
                          key={step.id}
                          className={cn(
                            "flex items-center gap-4 rounded-lg border p-4 transition-all duration-300",
                            step.status === "complete" &&
                            "border-success/30 bg-success/5",
                            step.status === "running" &&
                            "border-primary/50 bg-primary/5",
                            step.status === "pending" &&
                            "border-border/30 bg-muted/20 opacity-50"
                          )}
                        >
                          <div
                            className={cn(
                              "flex h-10 w-10 items-center justify-center rounded-full",
                              step.status === "complete" &&
                              "bg-success/20 text-success",
                              step.status === "running" &&
                              "bg-primary/20 text-primary",
                              step.status === "pending" &&
                              "bg-muted text-muted-foreground"
                            )}
                          >
                            {step.status === "running" ? (
                              <Loader2 className="h-5 w-5 animate-spin" />
                            ) : step.status === "complete" ? (
                              <CheckCircle2 className="h-5 w-5" />
                            ) : (
                              step.icon
                            )}
                          </div>
                          <div className="flex-1">
                            <p
                              className={cn(
                                "font-medium",
                                step.status === "complete" && "text-success",
                                step.status === "running" && "text-primary",
                                step.status === "pending" && "text-muted-foreground"
                              )}
                            >
                              {step.label}
                            </p>
                            <p className="text-sm text-muted-foreground">
                              {step.status === "running"
                                ? "In progress..."
                                : step.status === "complete"
                                  ? "Completed"
                                  : "Waiting..."}
                            </p>
                          </div>
                          <Badge
                            variant={
                              step.status === "complete"
                                ? "default"
                                : step.status === "running"
                                  ? "secondary"
                                  : "outline"
                            }
                            className={cn(
                              step.status === "complete" &&
                              "bg-success/20 text-success border-success/30"
                            )}
                          >
                            {step.status === "running"
                              ? "Running"
                              : step.status === "complete"
                                ? "Done"
                                : `Step ${index + 1}`}
                          </Badge>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>

                {/* ── ML Results ─────────────────────────────────────────── */}
                {analysisResults && (
                  <>
                    {/* Summary Stats */}
                    <div className="grid gap-4 sm:grid-cols-4">
                      <Card className="border-border/50 bg-card/50 backdrop-blur-sm">
                        <CardContent className="pt-6 text-center">
                          <p className="text-3xl font-bold text-foreground">
                            {analysisResults.total_prs_analyzed}
                          </p>
                          <p className="text-sm text-muted-foreground">PRs Analyzed</p>
                        </CardContent>
                      </Card>
                      <Card className="border-red-500/30 bg-red-500/5">
                        <CardContent className="pt-6 text-center">
                          <p className="text-3xl font-bold text-red-400">
                            {analysisResults.high_risk_count}
                          </p>
                          <p className="text-sm text-muted-foreground">High Risk</p>
                        </CardContent>
                      </Card>
                      <Card className="border-emerald-500/30 bg-emerald-500/5">
                        <CardContent className="pt-6 text-center">
                          <p className="text-3xl font-bold text-emerald-400">
                            {analysisResults.low_risk_count}
                          </p>
                          <p className="text-sm text-muted-foreground">Low Risk</p>
                        </CardContent>
                      </Card>
                      <Card className="border-border/50 bg-card/50 backdrop-blur-sm">
                        <CardContent className="pt-6 text-center">
                          <p className="text-3xl font-bold text-foreground">
                            {(analysisResults.avg_risk_score * 100).toFixed(1)}%
                          </p>
                          <p className="text-sm text-muted-foreground">Avg Risk</p>
                        </CardContent>
                      </Card>
                    </div>

                    {/* PR Predictions Table */}
                    <Card className="border-border/50 bg-card/50 backdrop-blur-sm">
                      <CardHeader>
                        <CardTitle className="flex items-center gap-2">
                          <BarChart3 className="h-5 w-5 text-violet-400" />
                          Individual PR Predictions
                        </CardTitle>
                        <CardDescription>
                          Each PR analyzed by the XGBoost model ({analysisResults.predictions[0]?.model_version || "xgboost_v1"})
                        </CardDescription>
                      </CardHeader>
                      <CardContent>
                        <div className="space-y-3">
                          {analysisResults.predictions.map((pr: any) => {
                            const isExpanded = expandedPR === pr.pr_number;
                            const importanceEntries = Object.entries(pr.feature_importance || {})
                              .sort(([, a]: any, [, b]: any) => b - a);
                            const topFeature = importanceEntries[0];
                            return (
                              <div
                                key={pr.pr_number}
                                className={cn(
                                  "rounded-lg border transition-all",
                                  pr.risk_label === "high"
                                    ? "border-red-500/30"
                                    : "border-emerald-500/30"
                                )}
                              >
                                {/* Clickable header row */}
                                <div
                                  className="flex items-center gap-4 p-4 cursor-pointer hover:bg-accent/5 transition-colors"
                                  onClick={() => setExpandedPR(isExpanded ? null : pr.pr_number)}
                                >
                                  {/* Risk badge */}
                                  <div
                                    className={cn(
                                      "flex h-12 w-12 shrink-0 items-center justify-center rounded-full text-sm font-bold",
                                      pr.risk_label === "high"
                                        ? "bg-red-500/20 text-red-400"
                                        : "bg-emerald-500/20 text-emerald-400"
                                    )}
                                  >
                                    {pr.risk_percentage.toFixed(0)}%
                                  </div>

                                  {/* PR info */}
                                  <div className="flex-1 min-w-0">
                                    <div className="flex items-center gap-2">
                                      <p className="font-medium text-foreground truncate">
                                        #{pr.pr_number} {pr.title}
                                      </p>
                                    </div>
                                    <div className="flex items-center gap-3 text-sm text-muted-foreground mt-1 flex-wrap">
                                      <span className="flex items-center gap-1">
                                        <Github className="h-3 w-3" />
                                        {pr.author}
                                      </span>
                                      <span>•</span>
                                      <span>{pr.state}</span>
                                      <span>•</span>
                                      <span>{pr.features.files_changed} files</span>
                                      <span>•</span>
                                      <span className="text-emerald-400">+{pr.features.lines_added}</span>
                                      <span className="text-red-400">-{pr.features.lines_deleted}</span>
                                      {topFeature && (
                                        <>
                                          <span>•</span>
                                          <span className="text-violet-400 text-xs">
                                            Top factor: {(topFeature[0] as string).replace(/_/g, ' ')}
                                          </span>
                                        </>
                                      )}
                                    </div>
                                  </div>

                                  {/* Risk label */}
                                  <Badge
                                    className={cn(
                                      "shrink-0",
                                      pr.risk_label === "high"
                                        ? "bg-red-500/20 text-red-400 border-red-500/30"
                                        : "bg-emerald-500/20 text-emerald-400 border-emerald-500/30"
                                    )}
                                  >
                                    {pr.risk_label === "high" ? "🔴 HIGH" : "🟢 LOW"}
                                  </Badge>

                                  {/* Expand / GitHub link */}
                                  <ChevronDown className={cn(
                                    "h-4 w-4 shrink-0 text-muted-foreground transition-transform",
                                    isExpanded && "rotate-180"
                                  )} />

                                  <a
                                    href={pr.url}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="shrink-0 text-muted-foreground hover:text-foreground transition-colors"
                                    onClick={(e) => e.stopPropagation()}
                                  >
                                    <ExternalLink className="h-4 w-4" />
                                  </a>
                                </div>

                                {/* Expandable feature importance */}
                                {isExpanded && (
                                  <div className="border-t border-border/50 px-4 pb-4 pt-3 space-y-4">
                                    <p className="text-sm font-medium text-foreground flex items-center gap-2">
                                      <BarChart3 className="h-4 w-4 text-violet-400" />
                                      Why this risk score?
                                    </p>
                                    <div className="space-y-2">
                                      {importanceEntries.filter(([, imp]: [string, any]) => imp > 0.001).map(([name, importance]: [string, any]) => {
                                        const pct = (importance * 100).toFixed(1);
                                        const featureVal = pr.features[name];
                                        const displayVal = typeof featureVal === 'number'
                                          ? (Number.isInteger(featureVal) ? featureVal : featureVal.toFixed(3))
                                          : featureVal;
                                        return (
                                          <div key={name}>
                                            <div className="flex items-center justify-between text-sm mb-1">
                                              <span className="text-muted-foreground capitalize">
                                                {name.replace(/_/g, ' ')}
                                                <span className="ml-2 text-xs font-mono text-foreground/60">
                                                  = {displayVal}
                                                </span>
                                              </span>
                                              <span className="font-mono text-xs text-violet-400">
                                                {pct}% contribution
                                              </span>
                                            </div>
                                            <div className="h-1.5 rounded-full bg-muted/30 overflow-hidden">
                                              <div
                                                className={cn(
                                                  "h-full rounded-full transition-all duration-500",
                                                  parseFloat(pct) > 15
                                                    ? "bg-linear-to-r from-violet-500 to-purple-500"
                                                    : parseFloat(pct) > 5
                                                      ? "bg-violet-500/50"
                                                      : "bg-muted-foreground/30"
                                                )}
                                                style={{ width: `${Math.min(importance * 100, 100)}%` }}
                                              />
                                            </div>
                                          </div>
                                        );
                                      })}
                                    </div>

                                    {/* Security Findings */}
                                    {pr.security_findings && pr.security_findings.length > 0 && (
                                      <div className="space-y-2">
                                        <p className="text-sm font-medium text-foreground flex items-center gap-2">
                                          <AlertTriangle className="h-4 w-4 text-amber-400" />
                                          Security Findings ({pr.security_findings.length})
                                        </p>
                                        <div className="space-y-1.5">
                                          {pr.security_findings.map((finding: string, i: number) => (
                                            <div
                                              key={i}
                                              className="flex items-start gap-2 rounded-md bg-red-500/5 border border-red-500/20 px-3 py-2"
                                            >
                                              <Shield className="h-3.5 w-3.5 mt-0.5 text-red-400 shrink-0" />
                                              <p className="text-xs text-red-300/90">{finding}</p>
                                            </div>
                                          ))}
                                        </div>
                                      </div>
                                    )}

                                    {/* Interpretation */}
                                    <div className="rounded-lg bg-muted/20 p-3">
                                      <p className="text-xs text-muted-foreground">
                                        <strong className="text-foreground">Interpretation:</strong>{' '}
                                        This PR scored <strong className={pr.risk_label === 'high' ? 'text-red-400' : 'text-emerald-400'}>
                                          {pr.risk_percentage.toFixed(1)}% risk
                                        </strong> primarily because{' '}
                                        <span className="text-foreground font-medium">
                                          {topFeature ? (topFeature[0] as string).replace(/_/g, ' ') : 'multiple factors'}
                                        </span>
                                        {' '}had a high value
                                        {importanceEntries[1] && importanceEntries[1][1] as number > 0.05 && (
                                          <>, combined with{' '}
                                            <span className="text-foreground font-medium">
                                              {(importanceEntries[1][0] as string).replace(/_/g, ' ')}
                                            </span></>
                                        )}.
                                        {(!pr.security_findings || pr.security_findings.length === 0) &&
                                          ' No specific security threats detected.'}
                                      </p>
                                    </div>
                                  </div>
                                )}
                              </div>
                            );
                          })}
                        </div>
                      </CardContent>
                    </Card>

                    {/* ── Scanner Results ─────────────────────────────────── */}
                    {scanResults && (
                      <>
                        {/* Scanner Overview Cards */}
                        <div className="grid gap-4 sm:grid-cols-3">
                          <Card className="border-border/50 bg-card/50 backdrop-blur-sm">
                            <CardContent className="pt-6 text-center">
                              <p className="text-3xl font-bold text-foreground">
                                {(scanResults.summary as any)?.total_issues ?? 0}
                              </p>
                              <p className="text-sm text-muted-foreground">Total Security Issues</p>
                            </CardContent>
                          </Card>

                          {(scanResults.scanner_results as any[]).map((sr: any) => (
                            <Card
                              key={sr.id}
                              className={cn(
                                "border-border/50 bg-card/50",
                                sr.issuesFound > 0
                                  ? sr.name === "Snyk"
                                    ? "border-amber-500/30 bg-amber-500/5"
                                    : "border-red-500/30 bg-red-500/5"
                                  : "border-emerald-500/30 bg-emerald-500/5"
                              )}
                            >
                              <CardContent className="pt-6 text-center">
                                <p className={cn(
                                  "text-3xl font-bold",
                                  sr.issuesFound > 0
                                    ? sr.name === "Snyk" ? "text-amber-400" : "text-red-400"
                                    : "text-emerald-400"
                                )}>
                                  {sr.issuesFound}
                                </p>
                                <p className="text-sm text-muted-foreground">
                                  {sr.name} {sr.name === "Snyk" ? "Vulnerabilities" : "Findings"}
                                </p>
                                <Badge variant="outline" className="mt-2 text-xs capitalize">
                                  {sr.status}
                                </Badge>
                              </CardContent>
                            </Card>
                          ))}
                        </div>

                        {/* Snyk Vulnerabilities */}
                        {(scanResults.snyk_vulnerabilities as any[]).length > 0 && (
                          <Card className="border-amber-500/20 bg-card/50 backdrop-blur-sm">
                            <CardHeader>
                              <CardTitle className="flex items-center gap-2 text-amber-400">
                                <Shield className="h-5 w-5" />
                                Snyk Vulnerabilities ({(scanResults.snyk_vulnerabilities as any[]).length})
                              </CardTitle>
                              <CardDescription>
                                Dependency vulnerabilities detected by Snyk
                              </CardDescription>
                            </CardHeader>
                            <CardContent>
                              <div className="space-y-3">
                                {(scanResults.snyk_vulnerabilities as any[]).map((vuln: any) => (
                                  <div
                                    key={vuln.id}
                                    className={cn(
                                      "rounded-lg border p-4",
                                      vuln.severity === "critical"
                                        ? "border-red-500/30 bg-red-500/5"
                                        : vuln.severity === "high"
                                        ? "border-amber-500/30 bg-amber-500/5"
                                        : vuln.severity === "medium"
                                        ? "border-yellow-500/30 bg-yellow-500/5"
                                        : "border-border/30 bg-muted/10"
                                    )}
                                  >
                                    <div className="flex items-start justify-between gap-3">
                                      <div className="flex-1 min-w-0">
                                        <p className="font-medium text-foreground">{vuln.title}</p>
                                        {vuln.description && (
                                          <p className="text-sm text-muted-foreground mt-1 line-clamp-2">
                                            {vuln.description}
                                          </p>
                                        )}
                                        <div className="flex flex-wrap gap-2 mt-2">
                                          {vuln.package && (
                                            <Badge variant="outline" className="text-xs font-mono">
                                              {vuln.package}
                                              {vuln.version ? `@${vuln.version}` : ""}
                                            </Badge>
                                          )}
                                          {vuln.cwe && (
                                            <Badge variant="outline" className="text-xs">
                                              {vuln.cwe}
                                            </Badge>
                                          )}
                                          {vuln.cvss != null && (
                                            <Badge variant="outline" className="text-xs">
                                              CVSS {Number(vuln.cvss).toFixed(1)}
                                            </Badge>
                                          )}
                                          {vuln.fixedVersion && (
                                            <Badge className="text-xs bg-emerald-500/20 text-emerald-400 border-emerald-500/30">
                                              Fix: {vuln.fixedVersion}
                                            </Badge>
                                          )}
                                        </div>
                                      </div>
                                      <Badge
                                        className={cn(
                                          "shrink-0 capitalize",
                                          vuln.severity === "critical"
                                            ? "bg-red-500/20 text-red-400 border-red-500/30"
                                            : vuln.severity === "high"
                                            ? "bg-amber-500/20 text-amber-400 border-amber-500/30"
                                            : vuln.severity === "medium"
                                            ? "bg-yellow-500/20 text-yellow-400 border-yellow-500/30"
                                            : "bg-muted text-muted-foreground"
                                        )}
                                      >
                                        {vuln.severity}
                                      </Badge>
                                    </div>
                                  </div>
                                ))}
                              </div>
                            </CardContent>
                          </Card>
                        )}

                        {/* Semgrep Findings */}
                        {(scanResults.semgrep_findings as any[]).length > 0 && (
                          <Card className="border-red-500/20 bg-card/50 backdrop-blur-sm">
                            <CardHeader>
                              <CardTitle className="flex items-center gap-2 text-red-400">
                                <ScanLine className="h-5 w-5" />
                                Semgrep Findings ({(scanResults.semgrep_findings as any[]).length})
                              </CardTitle>
                              <CardDescription>
                                Static analysis findings from Semgrep SAST
                              </CardDescription>
                            </CardHeader>
                            <CardContent>
                              <div className="space-y-3">
                                {(scanResults.semgrep_findings as any[]).map((finding: any) => (
                                  <div
                                    key={finding.id}
                                    className={cn(
                                      "rounded-lg border p-4",
                                      finding.severity === "critical"
                                        ? "border-red-500/30 bg-red-500/5"
                                        : finding.severity === "high"
                                        ? "border-amber-500/30 bg-amber-500/5"
                                        : finding.severity === "medium"
                                        ? "border-yellow-500/30 bg-yellow-500/5"
                                        : "border-border/30 bg-muted/10"
                                    )}
                                  >
                                    <div className="flex items-start justify-between gap-3">
                                      <div className="flex-1 min-w-0">
                                        <p className="font-medium text-foreground">{finding.message}</p>
                                        <div className="flex flex-wrap gap-2 mt-2">
                                          <Badge variant="outline" className="text-xs font-mono">
                                            {finding.ruleId}
                                          </Badge>
                                          {finding.path && (
                                            <Badge variant="outline" className="text-xs">
                                              {finding.path}
                                              {finding.startLine ? `:${finding.startLine}` : ""}
                                            </Badge>
                                          )}
                                        </div>
                                        {finding.snippet && (
                                          <pre className="mt-2 rounded bg-muted/30 px-3 py-2 text-xs font-mono text-muted-foreground overflow-x-auto max-h-24">
                                            {finding.snippet}
                                          </pre>
                                        )}
                                      </div>
                                      <Badge
                                        className={cn(
                                          "shrink-0 capitalize",
                                          finding.severity === "critical"
                                            ? "bg-red-500/20 text-red-400 border-red-500/30"
                                            : finding.severity === "high"
                                            ? "bg-amber-500/20 text-amber-400 border-amber-500/30"
                                            : finding.severity === "medium"
                                            ? "bg-yellow-500/20 text-yellow-400 border-yellow-500/30"
                                            : "bg-muted text-muted-foreground"
                                        )}
                                      >
                                        {finding.severity}
                                      </Badge>
                                    </div>
                                  </div>
                                ))}
                              </div>
                            </CardContent>
                          </Card>
                        )}

                        {/* No issues found */}
                        {(scanResults.snyk_vulnerabilities as any[]).length === 0 &&
                          (scanResults.semgrep_findings as any[]).length === 0 && (
                          <Card className="border-emerald-500/20 bg-emerald-500/5">
                            <CardContent className="flex items-center gap-4 pt-6 pb-6">
                              <CheckCircle2 className="h-8 w-8 text-emerald-400 shrink-0" />
                              <div>
                                <p className="font-semibold text-emerald-400">
                                  No Security Issues Found
                                </p>
                                <p className="text-sm text-muted-foreground">
                                  Snyk and Semgrep found no vulnerabilities or code issues.
                                </p>
                              </div>
                            </CardContent>
                          </Card>
                        )}
                      </>
                    )}

                    {/* Scanner unavailable notice */}
                    {!scanResults && analysisResults && (
                      <Card className="border-border/50 bg-card/50">
                        <CardContent className="flex items-center gap-3 pt-6 pb-6">
                          <AlertTriangle className="h-5 w-5 text-amber-400 shrink-0" />
                          <div>
                            <p className="font-medium text-foreground">
                              Scanner Results Unavailable
                            </p>
                            <p className="text-sm text-muted-foreground">
                              Snyk / Semgrep could not be reached. Ensure they are
                              installed on the server and the repo URL is accessible.
                            </p>
                          </div>
                        </CardContent>
                      </Card>
                    )}

                    {/* New Analysis Button */}
                    <div className="flex justify-center">
                      <Button
                        size="lg"
                        variant="outline"
                        className="gap-2"
                        onClick={() => {
                          setIsAnalyzing(false);
                          setAnalysisResults(null);
                          setScanResults(null);
                          setAnalysisProgress(0);
                          setCurrentStep(0);
                        }}
                      >
                        <GitBranch className="h-4 w-4" />
                        Analyze Another Repository
                      </Button>
                    </div>
                  </>
                )}
              </div>
            ) : (
              <form onSubmit={handleSubmit} className="space-y-6">
                {/* Submission Method Toggle */}
                <Card className="border-border/50 bg-card/50 backdrop-blur-sm">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Link className="h-5 w-5 text-primary" />
                      Submission Method
                    </CardTitle>
                    <CardDescription>
                      Choose how you want to submit your pull request
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="grid grid-cols-2 gap-4">
                      <button
                        type="button"
                        onClick={() => setSubmissionMethod("url")}
                        className={cn(
                          "flex flex-col items-center gap-3 rounded-lg border-2 p-6 transition-all",
                          submissionMethod === "url"
                            ? "border-primary bg-primary/5"
                            : "border-border/50 hover:border-border hover:bg-muted/30"
                        )}
                      >
                        <div
                          className={cn(
                            "flex h-12 w-12 items-center justify-center rounded-full",
                            submissionMethod === "url"
                              ? "bg-primary/20 text-primary"
                              : "bg-muted text-muted-foreground"
                          )}
                        >
                          <Github className="h-6 w-6" />
                        </div>
                        <div className="text-center">
                          <p className="font-semibold text-foreground">
                            PR URL
                          </p>
                          <p className="text-sm text-muted-foreground">
                            Paste GitHub/GitLab PR link
                          </p>
                        </div>
                      </button>

                      <button
                        type="button"
                        onClick={() => setSubmissionMethod("manual")}
                        className={cn(
                          "flex flex-col items-center gap-3 rounded-lg border-2 p-6 transition-all",
                          submissionMethod === "manual"
                            ? "border-primary bg-primary/5"
                            : "border-border/50 hover:border-border hover:bg-muted/30"
                        )}
                      >
                        <div
                          className={cn(
                            "flex h-12 w-12 items-center justify-center rounded-full",
                            submissionMethod === "manual"
                              ? "bg-primary/20 text-primary"
                              : "bg-muted text-muted-foreground"
                          )}
                        >
                          <Code2 className="h-6 w-6" />
                        </div>
                        <div className="text-center">
                          <p className="font-semibold text-foreground">
                            Manual Entry
                          </p>
                          <p className="text-sm text-muted-foreground">
                            Paste diff content directly
                          </p>
                        </div>
                      </button>
                    </div>
                  </CardContent>
                </Card>

                {/* PR Details */}
                <Card className="border-border/50 bg-card/50 backdrop-blur-sm">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <GitPullRequest className="h-5 w-5 text-primary" />
                      PR Details
                    </CardTitle>
                    <CardDescription>
                      {submissionMethod === "url"
                        ? "Enter the pull request URL to analyze"
                        : "Enter the pull request details manually"}
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    {submissionMethod === "url" ? (
                      <div className="space-y-2">
                        <Label htmlFor="prUrl">Pull Request URL</Label>
                        <div className="relative">
                          <Github className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                          <Input
                            id="prUrl"
                            placeholder="https://github.com/org/repo/pull/123"
                            value={formData.prUrl}
                            onChange={(e) =>
                              setFormData({ ...formData, prUrl: e.target.value })
                            }
                            className="pl-10"
                          />
                        </div>
                        <p className="text-xs text-muted-foreground">
                          Supports GitHub, GitLab, and Bitbucket URLs
                        </p>
                      </div>
                    ) : (
                      <>
                        <div className="grid grid-cols-2 gap-4">
                          <div className="space-y-2">
                            <Label htmlFor="repository">Repository</Label>
                            <div className="relative">
                              <FileCode className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                              <Input
                                id="repository"
                                placeholder="org/repository"
                                value={formData.repository}
                                onChange={(e) =>
                                  setFormData({
                                    ...formData,
                                    repository: e.target.value,
                                  })
                                }
                                className="pl-10"
                              />
                            </div>
                          </div>
                          <div className="space-y-2">
                            <Label htmlFor="branch">Branch</Label>
                            <div className="relative">
                              <GitBranch className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                              <Input
                                id="branch"
                                placeholder="feature/new-feature"
                                value={formData.branch}
                                onChange={(e) =>
                                  setFormData({
                                    ...formData,
                                    branch: e.target.value,
                                  })
                                }
                                className="pl-10"
                              />
                            </div>
                          </div>
                        </div>

                        <div className="space-y-2">
                          <Label htmlFor="title">PR Title</Label>
                          <Input
                            id="title"
                            placeholder="Add new authentication feature"
                            value={formData.title}
                            onChange={(e) =>
                              setFormData({ ...formData, title: e.target.value })
                            }
                          />
                        </div>

                        <div className="space-y-2">
                          <Label htmlFor="description">Description</Label>
                          <Textarea
                            id="description"
                            placeholder="Describe the changes in this PR..."
                            value={formData.description}
                            onChange={(e) =>
                              setFormData({
                                ...formData,
                                description: e.target.value,
                              })
                            }
                            rows={3}
                          />
                        </div>

                        <div className="space-y-2">
                          <Label htmlFor="diffContent">Code Diff</Label>
                          <Textarea
                            id="diffContent"
                            placeholder="Paste your git diff content here..."
                            value={formData.diffContent}
                            onChange={(e) =>
                              setFormData({
                                ...formData,
                                diffContent: e.target.value,
                              })
                            }
                            rows={10}
                            className="font-mono text-sm"
                          />
                        </div>
                      </>
                    )}
                  </CardContent>
                </Card>

                {/* Analysis Options */}
                <Card className="border-border/50 bg-card/50 backdrop-blur-sm">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Zap className="h-5 w-5 text-primary" />
                      Analysis Options
                    </CardTitle>
                    <CardDescription>
                      Configure which analysis features to enable
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-6">
                    <div className="grid gap-4 md:grid-cols-3">
                      <div
                        className={cn(
                          "flex items-center justify-between rounded-lg border p-4 transition-colors",
                          formData.enableAI
                            ? "border-primary/30 bg-primary/5"
                            : "border-border/50"
                        )}
                      >
                        <div className="flex items-center gap-3">
                          <div
                            className={cn(
                              "flex h-9 w-9 items-center justify-center rounded-lg",
                              formData.enableAI
                                ? "bg-primary/20 text-primary"
                                : "bg-muted text-muted-foreground"
                            )}
                          >
                            <Brain className="h-4 w-4" />
                          </div>
                          <div>
                            <p className="font-medium text-foreground">
                              AI Analysis
                            </p>
                            <p className="text-xs text-muted-foreground">
                              GPT-4 powered
                            </p>
                          </div>
                        </div>
                        <Switch
                          checked={formData.enableAI}
                          onCheckedChange={(checked: boolean) =>
                            setFormData({ ...formData, enableAI: checked })
                          }
                        />
                      </div>

                      <div
                        className={cn(
                          "flex items-center justify-between rounded-lg border p-4 transition-colors",
                          formData.enableML
                            ? "border-accent/30 bg-accent/5"
                            : "border-border/50"
                        )}
                      >
                        <div className="flex items-center gap-3">
                          <div
                            className={cn(
                              "flex h-9 w-9 items-center justify-center rounded-lg",
                              formData.enableML
                                ? "bg-accent/20 text-accent"
                                : "bg-muted text-muted-foreground"
                            )}
                          >
                            <Sparkles className="h-4 w-4" />
                          </div>
                          <div>
                            <p className="font-medium text-foreground">
                              ML Scoring
                            </p>
                            <p className="text-xs text-muted-foreground">
                              Risk prediction
                            </p>
                          </div>
                        </div>
                        <Switch
                          checked={formData.enableML}
                          onCheckedChange={(checked: boolean) =>
                            setFormData({ ...formData, enableML: checked })
                          }
                        />
                      </div>

                      <div
                        className={cn(
                          "flex items-center justify-between rounded-lg border p-4 transition-colors",
                          formData.enableSecurityScan
                            ? "border-success/30 bg-success/5"
                            : "border-border/50"
                        )}
                      >
                        <div className="flex items-center gap-3">
                          <div
                            className={cn(
                              "flex h-9 w-9 items-center justify-center rounded-lg",
                              formData.enableSecurityScan
                                ? "bg-success/20 text-success"
                                : "bg-muted text-muted-foreground"
                            )}
                          >
                            <Shield className="h-4 w-4" />
                          </div>
                          <div>
                            <p className="font-medium text-foreground">
                              Security Scan
                            </p>
                            <p className="text-xs text-muted-foreground">
                              SAST/Secrets
                            </p>
                          </div>
                        </div>
                        <Switch
                          checked={formData.enableSecurityScan}
                          onCheckedChange={(checked: boolean) =>
                            setFormData({
                              ...formData,
                              enableSecurityScan: checked,
                            })
                          }
                        />
                      </div>
                    </div>

                    <div className="grid gap-4 md:grid-cols-2">
                      <div className="space-y-2">
                        <Label htmlFor="priority">Analysis Priority</Label>
                        <Select
                          value={formData.priority}
                          onValueChange={(value: string) =>
                            setFormData({ ...formData, priority: value })
                          }
                        >
                          <SelectTrigger id="priority">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="low">
                              <span className="flex items-center gap-2">
                                <span className="h-2 w-2 rounded-full bg-muted-foreground" />
                                Low Priority
                              </span>
                            </SelectItem>
                            <SelectItem value="normal">
                              <span className="flex items-center gap-2">
                                <span className="h-2 w-2 rounded-full bg-primary" />
                                Normal Priority
                              </span>
                            </SelectItem>
                            <SelectItem value="high">
                              <span className="flex items-center gap-2">
                                <span className="h-2 w-2 rounded-full bg-warning" />
                                High Priority
                              </span>
                            </SelectItem>
                            <SelectItem value="critical">
                              <span className="flex items-center gap-2">
                                <span className="h-2 w-2 rounded-full bg-critical" />
                                Critical Priority
                              </span>
                            </SelectItem>
                          </SelectContent>
                        </Select>
                      </div>

                      <div className="flex items-end">
                        <div className="flex w-full items-center justify-between rounded-lg border border-border/50 p-4">
                          <div className="flex items-center gap-3">
                            <AlertTriangle className="h-4 w-4 text-muted-foreground" />
                            <span className="text-sm text-foreground">
                              Notify on completion
                            </span>
                          </div>
                          <Switch
                            checked={formData.notifyOnComplete}
                            onCheckedChange={(checked: boolean) =>
                              setFormData({
                                ...formData,
                                notifyOnComplete: checked,
                              })
                            }
                          />
                        </div>
                      </div>
                    </div>
                  </CardContent>
                </Card>

                {/* Submit Button */}
                <div className="flex items-center justify-between">
                  <p className="text-sm text-muted-foreground">
                    Analysis typically takes 30-60 seconds
                  </p>
                  <Button
                    type="submit"
                    size="lg"
                    className="gap-2 bg-primary hover:bg-primary/90"
                  >
                    <Upload className="h-4 w-4" />
                    Start Analysis
                  </Button>
                </div>
              </form>
            )}
          </div>
        </main>
      </div>
    </div>
  );
}
