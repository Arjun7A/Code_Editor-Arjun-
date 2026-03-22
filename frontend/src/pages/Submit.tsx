import { useEffect, useMemo, useState } from "react";
import { CheckCircle2, Github, Loader2, Shield, Sparkles } from "lucide-react";
import { Header } from "@/components/layout/header";
import { Sidebar } from "@/components/layout/sidebar";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { useToast } from "@/hooks/use-toast";
import { analyzePR } from "@/lib/api";
import type { ScanRecord } from "@/lib/types";
import { ScanResultsView } from "@/components/scan/scan-results-view";

const progressMessages = [
  "Connecting to the SecureAudit backend",
  "Cloning the repository and fetching the PR diff",
  "Running Semgrep and OSV Scanner",
  "Checking for secrets with Gitleaks",
  "Reviewing Dockerfile and workflows with Checkov",
  "Running the AI agent review",
];

function isGitHubRepoUrl(value: string) {
  return /^https:\/\/github\.com\/[^/]+\/[^/]+\/?$/.test(value.trim());
}

function isGitHubPrUrl(value: string) {
  return /^https:\/\/github\.com\/[^/]+\/[^/]+\/pull\/\d+\/?$/.test(value.trim());
}

export default function SubmitPRPage() {
  const { toast } = useToast();
  const [repoUrl, setRepoUrl] = useState("");
  const [prUrl, setPrUrl] = useState("");
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [progress, setProgress] = useState(8);
  const [messageIndex, setMessageIndex] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ScanRecord | null>(null);

  useEffect(() => {
    if (!isAnalyzing) {
      return undefined;
    }

    const progressTimer = window.setInterval(() => {
      setProgress((current) => Math.min(current + 6, 92));
    }, 6000);

    const messageTimer = window.setInterval(() => {
      setMessageIndex((current) => (current + 1) % progressMessages.length);
    }, 5000);

    return () => {
      window.clearInterval(progressTimer);
      window.clearInterval(messageTimer);
    };
  }, [isAnalyzing]);

  const currentMessage = useMemo(
    () => progressMessages[messageIndex],
    [messageIndex]
  );

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault();

    const trimmedRepo = repoUrl.trim();
    const trimmedPr = prUrl.trim();

    if (!trimmedRepo || !trimmedPr) {
      setError("Repository URL and PR URL are both required.");
      return;
    }

    if (!isGitHubRepoUrl(trimmedRepo)) {
      setError("Repository URL must be a GitHub repository URL like https://github.com/owner/repo.");
      return;
    }

    if (!isGitHubPrUrl(trimmedPr)) {
      setError("PR URL must be a GitHub pull request URL like https://github.com/owner/repo/pull/123.");
      return;
    }

    setIsAnalyzing(true);
    setProgress(12);
    setMessageIndex(0);
    setError(null);
    setResult(null);

    try {
      const scanResult = await analyzePR(trimmedRepo, trimmedPr);
      setResult(scanResult);
      setProgress(100);

      toast({
        title: "Scan complete",
        description: `Found ${scanResult.scan_summary.total_issues} total issues across all tools.`,
      });
    } catch (submitError) {
      const message =
        submitError instanceof Error
          ? submitError.message
          : "We couldn't start the PR scan.";

      setError(message);
      toast({
        title: "Scan failed",
        description: message,
        variant: "destructive",
      });
    } finally {
      setIsAnalyzing(false);
    }
  }

  return (
    <div className="flex h-screen bg-background">
      <Sidebar />

      <div className="flex flex-1 flex-col overflow-hidden">
        <Header />

        <main className="flex-1 overflow-y-auto p-6">
          <div className="mx-auto max-w-5xl space-y-6">
            <div>
              <h1 className="text-3xl font-bold text-foreground">
                Submit PR for Analysis
              </h1>
              <p className="mt-2 text-muted-foreground">
                Scan a GitHub pull request with Semgrep, OSV Scanner, Gitleaks,
                Checkov, and the AI agent.
              </p>
            </div>

            <Card className="border-border/60 bg-card/80">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Github className="h-5 w-5 text-primary" />
                  GitHub Pull Request
                </CardTitle>
                <CardDescription>
                  Both the repository URL and PR URL are required.
                </CardDescription>
              </CardHeader>

              <CardContent>
                <form onSubmit={handleSubmit} className="space-y-6">
                  <div className="space-y-2">
                    <Label htmlFor="repo-url">Repository URL</Label>
                    <Input
                      id="repo-url"
                      value={repoUrl}
                      onChange={(event) => setRepoUrl(event.target.value)}
                      placeholder="https://github.com/owner/repo"
                    />
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="pr-url">PR URL</Label>
                    <Input
                      id="pr-url"
                      value={prUrl}
                      onChange={(event) => setPrUrl(event.target.value)}
                      placeholder="https://github.com/owner/repo/pull/123"
                    />
                  </div>

                  {error ? (
                    <div className="rounded-lg border border-destructive/40 bg-destructive/10 p-4 text-sm text-destructive">
                      {error}
                    </div>
                  ) : null}

                  <div className="flex items-center justify-between gap-4">
                    <p className="text-sm text-muted-foreground">
                      Scanning PR... This may take 2-5 minutes.
                    </p>

                    <Button
                      type="submit"
                      disabled={isAnalyzing}
                      className="min-w-40 gap-2"
                    >
                      {isAnalyzing ? (
                        <>
                          <Loader2 className="h-4 w-4 animate-spin" />
                          Scanning...
                        </>
                      ) : (
                        <>
                          <Shield className="h-4 w-4" />
                          Start Analysis
                        </>
                      )}
                    </Button>
                  </div>
                </form>
              </CardContent>
            </Card>

            {isAnalyzing ? (
              <Card className="border-border/60 bg-card/80">
                <CardContent className="space-y-6 pt-6">
                  <div className="flex items-start gap-4">
                    <div className="rounded-full bg-primary/10 p-4">
                      <Sparkles className="h-6 w-6 animate-pulse text-primary" />
                    </div>

                    <div className="space-y-2">
                      <p className="text-lg font-semibold text-foreground">
                        Scanning PR... This may take 2-5 minutes
                      </p>
                      <p className="text-sm text-muted-foreground">
                        {currentMessage}
                      </p>
                    </div>
                  </div>

                  <div className="space-y-2">
                    <div className="flex items-center justify-between text-sm">
                      <span className="text-muted-foreground">Progress</span>
                      <span className="font-medium text-foreground">{progress}%</span>
                    </div>
                    <Progress value={progress} className="h-2" />
                  </div>
                </CardContent>
              </Card>
            ) : null}

            {result ? (
              <Card className="border-emerald-500/30 bg-emerald-500/5">
                <CardContent className="flex items-center gap-3 pt-6 text-emerald-300">
                  <CheckCircle2 className="h-5 w-5" />
                  <div>
                    <p className="font-medium">Scan complete</p>
                    <p className="text-sm text-emerald-200/80">
                      Review the findings below and use them to fix the PR before merging.
                    </p>
                  </div>
                </CardContent>
              </Card>
            ) : null}

            {result ? <ScanResultsView scan={result} /> : null}
          </div>
        </main>
      </div>
    </div>
  );
}
