import { useMemo, useState, type ReactNode } from "react";
import type { LucideIcon } from "lucide-react";
import {
  Bot,
  Braces,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Copy,
  ExternalLink,
  FileCode2,
  FileKey2,
  FolderGit2,
  GitPullRequest,
  Info,
  PackageSearch,
  Shield,
  ShieldAlert,
  Sparkles,
  Wrench,
} from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import type {
  AIFinding,
  CheckovFinding,
  GitleaksFinding,
  IssueFinding,
  ScanRecord,
  Severity,
} from "@/lib/types";
import {
  SEVERITY_META,
  TOOL_META,
  formatFixText,
  getSeverityBadgeStyle,
  getToolBadgeStyle,
  getTotalIssues,
  hexToRgba,
  sortIssuesBySeverity,
} from "@/lib/scan-utils";

interface ScanResultsViewProps {
  scan: ScanRecord;
}

interface MetaItem {
  label: string;
  value?: string | number | null;
  monospace?: boolean;
}

const summaryMetricConfig: Array<{
  key: string;
  label: string;
  icon: LucideIcon;
  color: string;
  getValue: (scan: ScanRecord) => number | string;
}> = [
  {
    key: "total_issues",
    label: "Total Issues",
    icon: ShieldAlert,
    color: "#ef4444",
    getValue: (scan) => getTotalIssues(scan),
  },
  {
    key: "semgrep",
    label: "Semgrep",
    icon: Shield,
    color: "#8b5cf6",
    getValue: (scan) => scan.scan_summary?.semgrep ?? 0,
  },
  {
    key: "osv",
    label: "OSV Scanner",
    icon: PackageSearch,
    color: "#06b6d4",
    getValue: (scan) => scan.scan_summary?.osv ?? 0,
  },
  {
    key: "ai_agent",
    label: "AI Agent",
    icon: Bot,
    color: "#3b82f6",
    getValue: (scan) => scan.scan_summary?.ai_agent ?? scan.ai_audit?.findings?.length ?? 0,
  },
  {
    key: "gitleaks",
    label: "Gitleaks",
    icon: FileKey2,
    color: "#ef4444",
    getValue: (scan) => scan.scan_summary?.gitleaks ?? scan.gitleaks.length,
  },
  {
    key: "checkov",
    label: "Checkov",
    icon: Wrench,
    color: "#22c55e",
    getValue: (scan) => scan.scan_summary?.checkov ?? scan.checkov.length,
  },
  {
    key: "pr_files_scanned",
    label: "PR Files Scanned",
    icon: FolderGit2,
    color: "#60a5fa",
    getValue: (scan) => scan.scan_summary?.pr_files_scanned ?? 0,
  },
];

export function ScanResultsView({ scan }: ScanResultsViewProps) {
  const aiFindings = sortIssuesBySeverity(scan.ai_audit?.findings ?? []);
  const issues = sortIssuesBySeverity(scan.issues ?? []);
  const gitleaks = sortIssuesBySeverity(scan.gitleaks ?? []);
  const checkov = sortIssuesBySeverity(scan.checkov ?? []);
  const rawJson = useMemo(() => JSON.stringify(scan, null, 2), [scan]);
  const [copied, setCopied] = useState(false);

  async function handleCopyJson() {
    try {
      await navigator.clipboard.writeText(rawJson);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1800);
    } catch {
      setCopied(false);
    }
  }

  return (
    <div className="space-y-6">
      <Card className="relative overflow-hidden border-border/60 bg-card/90">
        <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_top_right,rgba(59,130,246,0.16),transparent_34%),radial-gradient(circle_at_left,rgba(139,92,246,0.14),transparent_28%),linear-gradient(180deg,rgba(255,255,255,0.02),transparent)]" />

        <CardHeader className="relative space-y-6">
          <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
            <div className="space-y-3">
              <div className="inline-flex items-center gap-2 rounded-full border border-primary/20 bg-primary/10 px-3 py-1 text-xs font-semibold uppercase tracking-[0.2em] text-primary">
                <Sparkles className="h-3.5 w-3.5" />
                Complete Backend Scan Report
              </div>

              <div className="space-y-2">
                <CardTitle className="flex items-center gap-2 text-2xl">
                  <Shield className="h-6 w-6 text-primary" />
                  Every JSON detail, rendered cleanly
                </CardTitle>
                <CardDescription className="max-w-3xl text-sm leading-6 text-muted-foreground">
                  This view keeps the full backend response visible in a more polished layout —
                  explanations, remediation guidance, before/after code, metadata, and the raw
                  JSON payload.
                </CardDescription>
              </div>
            </div>

            <div className="flex flex-wrap gap-2">
              <StatusPill
                icon={ShieldAlert}
                label={`${getTotalIssues(scan)} total findings`}
                color="#ef4444"
              />
              <StatusPill
                icon={FolderGit2}
                label={`${scan.scan_summary?.pr_files_scanned ?? 0} files scanned`}
                color="#60a5fa"
              />
              <StatusPill
                icon={Bot}
                label={`AI ${scan.ai_audit?.status ?? "unknown"}`}
                color="#3b82f6"
              />
            </div>
          </div>

          <div className="grid gap-4 lg:grid-cols-2">
            <ScanLinkCard
              label="Repository URL"
              value={scan.repo_url}
              icon={FolderGit2}
            />
            <ScanLinkCard
              label="Pull Request URL"
              value={scan.pr_url}
              icon={GitPullRequest}
            />
          </div>

          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            {summaryMetricConfig.map((item) => (
              <SummaryMetricCard
                key={item.key}
                label={item.label}
                value={item.getValue(scan)}
                icon={item.icon}
                color={item.color}
              />
            ))}
          </div>
        </CardHeader>
      </Card>

      <Tabs defaultValue="details" className="space-y-4">
        <TabsList className="h-auto w-full justify-start gap-2 rounded-xl bg-muted/40 p-1.5">
          <TabsTrigger value="details" className="px-4 py-2">
            Detailed Findings
          </TabsTrigger>
          <TabsTrigger value="raw-json" className="px-4 py-2">
            Raw JSON
          </TabsTrigger>
        </TabsList>

        <TabsContent value="details" className="space-y-6">
          <SectionCard
            title="Semgrep & OSV Findings"
            description="Static analysis and dependency vulnerability issues coming from the shared issues array."
            icon={ShieldAlert}
            count={issues.length}
            accentColor="#8b5cf6"
          >
            {issues.length === 0 ? (
              <CleanBanner message="No Semgrep or OSV issues detected." />
            ) : (
              <div className="space-y-4">
                {issues.map((issue, index) => (
                  <IssueCard
                    key={`${issue.tool}-${issue.file ?? "file"}-${issue.line ?? index}-${index}`}
                    issue={issue}
                  />
                ))}
              </div>
            )}
          </SectionCard>

          <SectionCard
            title="AI Agent Audit"
            description="Deep reasoning from the Groq-hosted LLaMA reviewer, including before/after fix guidance when available."
            icon={Bot}
            count={aiFindings.length}
            accentColor="#3b82f6"
            aside={
              <div className="flex flex-wrap gap-2">
                <StatusPill
                  icon={Bot}
                  label={`Status: ${scan.ai_audit?.status ?? "unknown"}`}
                  color="#3b82f6"
                />
                {scan.ai_audit?.model ? (
                  <StatusPill
                    icon={Braces}
                    label={scan.ai_audit.model}
                    color="#60a5fa"
                  />
                ) : null}
              </div>
            }
          >
            {scan.ai_audit?.error ? (
              <div className="mb-4 rounded-xl border border-amber-500/40 bg-amber-500/10 p-4 text-sm text-amber-200">
                <p className="font-medium text-amber-100">AI audit note</p>
                <p className="mt-1">{scan.ai_audit.error}</p>
              </div>
            ) : null}

            {aiFindings.length === 0 ? (
              <CleanBanner message="No AI findings — PR looks clean." />
            ) : (
              <div className="space-y-4">
                {aiFindings.map((finding, index) => (
                  <AIFindingCard
                    key={`${finding.title}-${finding.file ?? "file"}-${index}`}
                    finding={finding}
                  />
                ))}
              </div>
            )}
          </SectionCard>

          <SectionCard
            title="Gitleaks"
            description="Secrets and hardcoded credential checks, including redacted values and remediation guidance."
            icon={FileKey2}
            count={gitleaks.length}
            accentColor="#ef4444"
          >
            {gitleaks.length === 0 ? (
              <CleanBanner message="No secrets detected." />
            ) : (
              <div className="space-y-4">
                {gitleaks.map((finding, index) => (
                  <GitleaksCard
                    key={`${finding.file ?? "file"}-${finding.line ?? index}-${index}`}
                    finding={finding}
                  />
                ))}
              </div>
            )}
          </SectionCard>

          <SectionCard
            title="Checkov"
            description="Infrastructure and CI/CD misconfiguration findings with the backend explanation and fix steps."
            icon={Wrench}
            count={checkov.length}
            accentColor="#22c55e"
          >
            {checkov.length === 0 ? (
              <CleanBanner message="No IaC misconfigurations." />
            ) : (
              <div className="space-y-4">
                {checkov.map((finding, index) => (
                  <CheckovCard
                    key={`${finding.rule_id ?? "rule"}-${finding.file ?? "file"}-${index}`}
                    finding={finding}
                  />
                ))}
              </div>
            )}
          </SectionCard>
        </TabsContent>

        <TabsContent value="raw-json">
          <Card className="border-border/60 bg-card/85">
            <CardHeader className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
              <div>
                <CardTitle className="flex items-center gap-2">
                  <Braces className="h-5 w-5 text-primary" />
                  Raw Backend JSON
                </CardTitle>
                <CardDescription>
                  Exact backend payload for this scan. Nothing is hidden here.
                </CardDescription>
              </div>

              <Button variant="outline" className="gap-2" onClick={handleCopyJson}>
                <Copy className="h-4 w-4" />
                {copied ? "Copied" : "Copy JSON"}
              </Button>
            </CardHeader>

            <CardContent>
              <ScrollArea className="h-[560px] rounded-xl border border-border/60 bg-background/70">
                <pre className="min-h-full whitespace-pre-wrap p-4 text-xs leading-6 text-foreground/90">
                  <code>{rawJson}</code>
                </pre>
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}

function ScanLinkCard({
  label,
  value,
  icon: Icon,
}: {
  label: string;
  value: string;
  icon: LucideIcon;
}) {
  return (
    <div className="rounded-2xl border border-border/60 bg-background/50 p-4 shadow-sm">
      <div className="flex items-start gap-3">
        <div className="rounded-xl border border-border/60 bg-card/70 p-2.5">
          <Icon className="h-4 w-4 text-primary" />
        </div>

        <div className="min-w-0 flex-1">
          <p className="text-xs font-semibold uppercase tracking-[0.18em] text-muted-foreground">
            {label}
          </p>
          <a
            href={value}
            target="_blank"
            rel="noreferrer"
            className="mt-2 inline-flex items-start gap-2 break-all text-sm text-primary hover:underline"
          >
            <span>{value}</span>
            <ExternalLink className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          </a>
        </div>
      </div>
    </div>
  );
}

function SummaryMetricCard({
  label,
  value,
  icon: Icon,
  color,
}: {
  label: string;
  value: string | number;
  icon: LucideIcon;
  color: string;
}) {
  return (
    <div
      className="rounded-2xl border bg-background/50 p-4 shadow-sm"
      style={{
        borderColor: hexToRgba(color, 0.32),
        background: `linear-gradient(180deg, ${hexToRgba(color, 0.12)}, rgba(15, 23, 42, 0.32))`,
      }}
    >
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.18em] text-muted-foreground">
            {label}
          </p>
          <p className="mt-3 text-3xl font-semibold text-foreground">{value}</p>
        </div>

        <div
          className="rounded-xl border p-2.5"
          style={{
            borderColor: hexToRgba(color, 0.32),
            backgroundColor: hexToRgba(color, 0.14),
          }}
        >
          <Icon className="h-4 w-4" style={{ color }} />
        </div>
      </div>
    </div>
  );
}

function StatusPill({
  icon: Icon,
  label,
  color,
}: {
  icon: LucideIcon;
  label: string;
  color: string;
}) {
  return (
    <div
      className="inline-flex items-center gap-2 rounded-full border px-3 py-1.5 text-xs font-medium"
      style={{
        borderColor: hexToRgba(color, 0.3),
        backgroundColor: hexToRgba(color, 0.14),
        color,
      }}
    >
      <Icon className="h-3.5 w-3.5" />
      <span>{label}</span>
    </div>
  );
}

function SectionCard({
  title,
  description,
  icon: Icon,
  count,
  accentColor,
  aside,
  children,
}: {
  title: string;
  description: string;
  icon: LucideIcon;
  count: number;
  accentColor: string;
  aside?: ReactNode;
  children: ReactNode;
}) {
  return (
    <Card className="relative overflow-hidden border-border/60 bg-card/85">
      <div
        className="pointer-events-none absolute inset-0"
        style={{
          background: `radial-gradient(circle at top right, ${hexToRgba(accentColor, 0.14)}, transparent 30%)`,
        }}
      />

      <CardHeader className="relative space-y-4">
        <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-3">
              <CardTitle className="flex items-center gap-2">
                <Icon className="h-5 w-5" style={{ color: accentColor }} />
                {title}
              </CardTitle>
              <Badge
                variant="outline"
                className="border font-semibold"
                style={{
                  borderColor: hexToRgba(accentColor, 0.35),
                  backgroundColor: hexToRgba(accentColor, 0.14),
                  color: accentColor,
                }}
              >
                {count} {count === 1 ? "finding" : "findings"}
              </Badge>
            </div>

            <CardDescription className="max-w-3xl text-sm leading-6">
              {description}
            </CardDescription>
          </div>

          {aside}
        </div>
      </CardHeader>

      <CardContent className="relative">{children}</CardContent>
    </Card>
  );
}

function CleanBanner({ message }: { message: string }) {
  return (
    <div className="flex items-start gap-3 rounded-2xl border border-emerald-500/35 bg-emerald-500/10 p-4 text-emerald-200">
      <div className="rounded-full border border-emerald-500/30 bg-emerald-500/15 p-2">
        <CheckCircle2 className="h-4 w-4 text-emerald-300" />
      </div>
      <div>
        <p className="font-medium text-emerald-100">{message}</p>
        <p className="mt-1 text-sm text-emerald-200/80">
          Empty results are a good sign — the backend did not return any findings for this tool.
        </p>
      </div>
    </div>
  );
}

function StyledBadge({
  label,
  style,
}: {
  label: string;
  style: { backgroundColor: string; color: string; borderColor: string };
}) {
  return (
    <Badge
      variant="outline"
      className="border font-semibold tracking-wide"
      style={style}
    >
      {label}
    </Badge>
  );
}

function FindingShell({
  title,
  severity,
  tool,
  previewItems = [],
  metaItems = [],
  children,
}: {
  title: string;
  severity: Severity;
  tool?: string;
  previewItems?: MetaItem[];
  metaItems?: MetaItem[];
  children: ReactNode;
}) {
  const [open, setOpen] = useState(true);
  const severityColor = SEVERITY_META[severity].color;

  return (
    <Collapsible open={open} onOpenChange={setOpen}>
      <div
        className="overflow-hidden rounded-2xl border bg-background/55 shadow-sm"
        style={{
          borderColor: hexToRgba(severityColor, 0.28),
          boxShadow: `0 16px 40px -28px ${hexToRgba(severityColor, 0.45)}`,
        }}
      >
        <CollapsibleTrigger className="flex w-full flex-col gap-4 p-5 text-left">
          <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
            <div className="space-y-3">
              <div className="flex flex-wrap items-center gap-2">
                {tool ? (
                  <StyledBadge
                    label={TOOL_META[tool]?.label ?? tool.toUpperCase()}
                    style={getToolBadgeStyle(tool)}
                  />
                ) : null}
                <StyledBadge
                  label={SEVERITY_META[severity].label}
                  style={getSeverityBadgeStyle(severity)}
                />
              </div>

              <div className="space-y-2">
                <p className="text-base font-semibold leading-6 text-foreground">{title}</p>
                <MetaPreview items={previewItems} />
              </div>
            </div>

            <div className="inline-flex items-center gap-2 text-xs font-medium text-muted-foreground">
              <span>{open ? "Hide details" : "Show details"}</span>
              {open ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
            </div>
          </div>
        </CollapsibleTrigger>

        <CollapsibleContent className="border-t border-border/50 bg-card/30 px-5 py-5">
          <div className="space-y-5">
            <MetaGrid items={metaItems} />
            {children}
          </div>
        </CollapsibleContent>
      </div>
    </Collapsible>
  );
}

function MetaPreview({ items }: { items: MetaItem[] }) {
  const visibleItems = items.filter((item) => hasValue(item.value));

  if (visibleItems.length === 0) {
    return null;
  }

  return (
    <div className="flex flex-wrap gap-2">
      {visibleItems.map((item) => (
        <div
          key={`${item.label}-${String(item.value)}`}
          className="inline-flex max-w-full items-center gap-2 rounded-full border border-border/60 bg-card/70 px-3 py-1 text-xs text-muted-foreground"
        >
          <span className="font-semibold text-foreground">{item.label}</span>
          <span className={item.monospace ? "font-mono text-[11px]" : ""}>{item.value}</span>
        </div>
      ))}
    </div>
  );
}

function MetaGrid({ items }: { items: MetaItem[] }) {
  const visibleItems = items.filter((item) => hasValue(item.value));

  if (visibleItems.length === 0) {
    return null;
  }

  return (
    <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
      {visibleItems.map((item) => (
        <div
          key={`${item.label}-${String(item.value)}`}
          className="rounded-xl border border-border/60 bg-background/55 p-3"
        >
          <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">
            {item.label}
          </p>
          <p
            className={`mt-2 break-all text-sm text-foreground ${
              item.monospace ? "font-mono text-[12px]" : ""
            }`}
          >
            {item.value}
          </p>
        </div>
      ))}
    </div>
  );
}

function IssueCard({ issue }: { issue: IssueFinding }) {
  const metaItems: MetaItem[] = [
    { label: "Tool", value: TOOL_META[issue.tool]?.label ?? issue.tool.toUpperCase() },
    { label: "Severity", value: SEVERITY_META[issue.severity].label },
    { label: "File", value: issue.file, monospace: true },
    { label: "Line", value: issue.line },
    { label: "Package", value: issue.package, monospace: true },
    { label: "Rule ID", value: issue.rule_id, monospace: true },
  ];

  return (
    <FindingShell
      title={issue.message}
      severity={issue.severity}
      tool={issue.tool}
      previewItems={[
        { label: "File", value: issue.file, monospace: true },
        { label: "Line", value: issue.line },
        { label: "Package", value: issue.package, monospace: true },
      ]}
      metaItems={metaItems}
    >
      <div className="grid gap-4 xl:grid-cols-2">
        <DetailPanel
          title="Explanation"
          icon={Info}
          text={issue.explanation}
          accentColor="#3b82f6"
          emptyText="No explanation was provided for this finding."
        />
        <DetailPanel
          title="Fix Guidance"
          icon={Wrench}
          text={issue.fix}
          accentColor="#22c55e"
          formatFix
          emptyText="No remediation guidance was provided for this finding."
        />
      </div>
    </FindingShell>
  );
}

function AIFindingCard({ finding }: { finding: AIFinding }) {
  const metaItems: MetaItem[] = [
    { label: "Severity", value: SEVERITY_META[finding.severity].label },
    { label: "File", value: finding.file, monospace: true },
    { label: "Category", value: finding.category },
    { label: "CWE", value: finding.cwe, monospace: true },
  ];

  return (
    <FindingShell
      title={finding.title}
      severity={finding.severity}
      tool="ai_agent"
      previewItems={[
        { label: "File", value: finding.file, monospace: true },
        { label: "Category", value: finding.category },
        { label: "CWE", value: finding.cwe, monospace: true },
      ]}
      metaItems={metaItems}
    >
      <div className="space-y-4">
        <DetailPanel
          title="Explanation"
          icon={Info}
          text={finding.explanation}
          accentColor="#3b82f6"
          emptyText="No explanation was provided for this AI finding."
        />

        {finding.fix?.summary ? (
          <DetailPanel
            title="Fix Summary"
            icon={Sparkles}
            text={finding.fix.summary}
            accentColor="#8b5cf6"
          />
        ) : null}

        {finding.fix?.before || finding.fix?.after ? (
          <div className="grid gap-4 xl:grid-cols-2">
            {finding.fix?.before ? <CodeBlock title="Before" code={finding.fix.before} /> : null}
            {finding.fix?.after ? <CodeBlock title="After" code={finding.fix.after} /> : null}
          </div>
        ) : null}

        <DetailPanel
          title="Fix Steps"
          icon={Wrench}
          text={finding.fix?.steps}
          accentColor="#22c55e"
          formatFix
          emptyText="No step-by-step remediation was provided for this AI finding."
        />
      </div>
    </FindingShell>
  );
}

function GitleaksCard({ finding }: { finding: GitleaksFinding }) {
  const metaItems: MetaItem[] = [
    { label: "Tool", value: "GITLEAKS" },
    { label: "Severity", value: "CRITICAL" },
    { label: "File", value: finding.file, monospace: true },
    { label: "Line", value: finding.line },
    { label: "Rule ID", value: finding.rule_id, monospace: true },
    { label: "Secret Type", value: finding.secret_type },
    { label: "Redacted", value: finding.redacted, monospace: true },
  ];

  return (
    <FindingShell
      title={finding.message}
      severity="critical"
      tool="gitleaks"
      previewItems={[
        { label: "File", value: finding.file, monospace: true },
        { label: "Line", value: finding.line },
        { label: "Redacted", value: finding.redacted, monospace: true },
      ]}
      metaItems={metaItems}
    >
      <div className="grid gap-4 xl:grid-cols-2">
        <DetailPanel
          title="Explanation"
          icon={Info}
          text={finding.explanation}
          accentColor="#ef4444"
          emptyText="No explanation was provided for this secret finding."
        />
        <DetailPanel
          title="Fix Steps"
          icon={Wrench}
          text={finding.fix}
          accentColor="#22c55e"
          formatFix
          emptyText="No remediation guidance was provided for this secret finding."
        />
      </div>
    </FindingShell>
  );
}

function CheckovCard({ finding }: { finding: CheckovFinding }) {
  const metaItems: MetaItem[] = [
    { label: "Tool", value: "CHECKOV" },
    { label: "Severity", value: SEVERITY_META[finding.severity].label },
    { label: "Check Name", value: finding.check_name || finding.message },
    { label: "Rule ID", value: finding.rule_id, monospace: true },
    { label: "File", value: finding.file, monospace: true },
    { label: "Line", value: finding.line },
    { label: "Resource", value: finding.resource, monospace: true },
  ];

  return (
    <FindingShell
      title={finding.check_name || finding.message}
      severity={finding.severity}
      tool="checkov"
      previewItems={[
        { label: "File", value: finding.file, monospace: true },
        { label: "Line", value: finding.line },
        { label: "Rule ID", value: finding.rule_id, monospace: true },
      ]}
      metaItems={metaItems}
    >
      <div className="grid gap-4 xl:grid-cols-2">
        <DetailPanel
          title="Explanation"
          icon={Info}
          text={finding.explanation}
          accentColor="#22c55e"
          emptyText="No explanation was provided for this Checkov finding."
        />
        <DetailPanel
          title="Fix Steps"
          icon={Wrench}
          text={finding.fix}
          accentColor="#22c55e"
          formatFix
          emptyText="No remediation guidance was provided for this Checkov finding."
        />
      </div>
    </FindingShell>
  );
}

function DetailPanel({
  title,
  text,
  icon: Icon,
  accentColor,
  formatFix = false,
  emptyText,
}: {
  title: string;
  text?: string | null;
  icon: LucideIcon;
  accentColor: string;
  formatFix?: boolean;
  emptyText?: string;
}) {
  const content = typeof text === 'string' ? text.trim() : null;

  return (
    <div
      className="rounded-2xl border p-4"
      style={{
        borderColor: hexToRgba(accentColor, 0.26),
        background: `linear-gradient(180deg, ${hexToRgba(accentColor, 0.08)}, rgba(15, 23, 42, 0.24))`,
      }}
    >
      <div className="flex items-center gap-2">
        <div
          className="rounded-lg border p-2"
          style={{
            borderColor: hexToRgba(accentColor, 0.3),
            backgroundColor: hexToRgba(accentColor, 0.14),
          }}
        >
          <Icon className="h-4 w-4" style={{ color: accentColor }} />
        </div>
        <p className="text-xs font-semibold uppercase tracking-[0.18em] text-muted-foreground">
          {title}
        </p>
      </div>

      <div className="mt-4">
        {content ? (
          formatFix ? (
            <FixContent text={content} accentColor={accentColor} />
          ) : (
            <TextContent text={content} />
          )
        ) : (
          <p className="text-sm leading-6 text-muted-foreground">
            {emptyText ?? "No additional detail was provided by the backend."}
          </p>
        )}
      </div>
    </div>
  );
}

function TextContent({ text }: { text: string }) {
  const paragraphs = text
    .split(/\n{2,}/)
    .map((segment) => segment.trim())
    .filter(Boolean);

  return (
    <div className="space-y-3 text-sm leading-7 text-foreground/90">
      {paragraphs.map((paragraph, index) => (
        <p key={`${paragraph.slice(0, 24)}-${index}`} className="whitespace-pre-wrap">
          {paragraph}
        </p>
      ))}
    </div>
  );
}

function FixContent({
  text,
  accentColor,
}: {
  text: string;
  accentColor: string;
}) {
  const normalized = formatFixText(text);
  const lines = normalized
    .split(/\n+/)
    .map((line) => line.trim())
    .filter(Boolean);
  const stepLines = lines.filter((line) => /^step\s+\d+/i.test(line));

  if (stepLines.length > 0) {
    return (
      <div className="space-y-3">
        {stepLines.map((line) => {
          const match = line.match(/^(Step\s+\d+)\s*[—-]\s*(.*)$/i);
          const label = match?.[1] ?? "Step";
          const body = match?.[2] ?? line;

          return (
            <div
              key={line}
              className="rounded-xl border p-3"
              style={{
                borderColor: hexToRgba(accentColor, 0.26),
                backgroundColor: hexToRgba(accentColor, 0.08),
              }}
            >
              <div className="flex items-start gap-3">
                <div
                  className="rounded-full border px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide"
                  style={{
                    borderColor: hexToRgba(accentColor, 0.3),
                    backgroundColor: hexToRgba(accentColor, 0.14),
                    color: accentColor,
                  }}
                >
                  {label}
                </div>
                <p className="text-sm leading-6 text-foreground/90">{body}</p>
              </div>
            </div>
          );
        })}

        {lines.filter((line) => !/^step\s+\d+/i.test(line)).map((line) => (
          <p key={line} className="text-sm leading-6 text-foreground/90">
            {line}
          </p>
        ))}
      </div>
    );
  }

  return <TextContent text={normalized} />;
}

function CodeBlock({ title, code }: { title: string; code: string }) {
  return (
    <div className="overflow-hidden rounded-2xl border border-border/60 bg-background/70">
      <div className="flex items-center gap-2 border-b border-border/60 bg-card/70 px-4 py-3">
        <div className="rounded-lg border border-border/60 bg-background/70 p-2">
          <FileCode2 className="h-4 w-4 text-primary" />
        </div>
        <p className="text-xs font-semibold uppercase tracking-[0.18em] text-muted-foreground">
          {title}
        </p>
      </div>

      <pre className="overflow-x-auto p-4 text-xs leading-6 text-foreground/90">
        <code>{code}</code>
      </pre>
    </div>
  );
}

function hasValue(value?: string | number | null): boolean {
  return value !== undefined && value !== null && value !== "";
}
