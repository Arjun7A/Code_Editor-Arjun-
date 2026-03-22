import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft, ExternalLink, Shield } from "lucide-react";
import { Header } from "@/components/layout/header";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { fetchPRAnalysis } from "@/lib/api";
import type { ScanRecord } from "@/lib/types";
import {
  formatTimestamp,
  getPrNumber,
  getRepoFullName,
  getTotalIssues,
} from "@/lib/scan-utils";
import { ScanResultsView } from "@/components/scan/scan-results-view";

export default function PRDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [scan, setScan] = useState<ScanRecord | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) {
      return;
    }

    void loadScan(id);
  }, [id]);

  async function loadScan(scanId: string) {
    setLoading(true);
    setError(null);

    try {
      const result = await fetchPRAnalysis(scanId);
      setScan(result);
    } catch (loadError) {
      const message =
        loadError instanceof Error
          ? loadError.message
          : "We couldn't load that saved scan.";
      setError(message);
      setScan(null);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen bg-background">
      <Header />

      <main className="mx-auto max-w-screen-xl px-4 py-6 lg:px-8">
        <div className="mb-6">
          <Button asChild variant="ghost" className="gap-2">
            <Link to="/audit-logs">
              <ArrowLeft className="h-4 w-4" />
              Back to Audit Logs
            </Link>
          </Button>
        </div>

        {loading ? (
          <Card className="border-border/60 bg-card/80">
            <CardContent className="pt-6 text-muted-foreground">
              Loading saved scan details...
            </CardContent>
          </Card>
        ) : null}

        {!loading && error ? (
          <Card className="border-border/60 bg-card/80">
            <CardContent className="pt-6 text-sm text-muted-foreground">
              <p className="font-medium text-foreground">Scan unavailable</p>
              <p className="mt-1">{error}</p>
            </CardContent>
          </Card>
        ) : null}

        {scan ? (
          <div className="space-y-6">
            <Card className="border-border/60 bg-card/80">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Shield className="h-5 w-5 text-primary" />
                  PR #{getPrNumber(scan.pr_url)} — {getRepoFullName(scan.repo_url)}
                </CardTitle>
                <CardDescription>
                  Saved scan completed on {formatTimestamp(scan.scanned_at)}
                </CardDescription>
              </CardHeader>
              <CardContent className="grid gap-3 md:grid-cols-3">
                <div className="rounded-lg border border-border/60 bg-background/40 p-3">
                  <p className="text-xs uppercase tracking-wide text-muted-foreground">
                    Total Issues
                  </p>
                  <p className="mt-2 text-2xl font-semibold text-foreground">
                    {getTotalIssues(scan)}
                  </p>
                </div>

                <div className="rounded-lg border border-border/60 bg-background/40 p-3">
                  <p className="text-xs uppercase tracking-wide text-muted-foreground">
                    Repository
                  </p>
                  <a
                    href={scan.repo_url}
                    target="_blank"
                    rel="noreferrer"
                    className="mt-2 inline-flex items-center gap-2 break-all text-sm text-primary hover:underline"
                  >
                    {scan.repo_url}
                    <ExternalLink className="h-3.5 w-3.5 shrink-0" />
                  </a>
                </div>

                <div className="rounded-lg border border-border/60 bg-background/40 p-3">
                  <p className="text-xs uppercase tracking-wide text-muted-foreground">
                    Pull Request
                  </p>
                  <a
                    href={scan.pr_url}
                    target="_blank"
                    rel="noreferrer"
                    className="mt-2 inline-flex items-center gap-2 break-all text-sm text-primary hover:underline"
                  >
                    {scan.pr_url}
                    <ExternalLink className="h-3.5 w-3.5 shrink-0" />
                  </a>
                </div>
              </CardContent>
            </Card>

            <ScanResultsView scan={scan} />
          </div>
        ) : null}
      </main>
    </div>
  );
}
