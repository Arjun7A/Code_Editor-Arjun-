"use client";

import React from "react"

import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  ChevronDown,
  ChevronRight,
  Shield,
  AlertTriangle,
  Bug,
  FileCode,
  ExternalLink,
  Info,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { RiskLevelBadge } from "@/components/ui/verdict-badge";
import { cn } from "@/lib/utils";
import type { Vulnerability, SemgrepFinding, RiskLevel } from "@/lib/types";

interface SecurityFindingsPanelProps {
  snykVulnerabilities: Vulnerability[];
  semgrepFindings: SemgrepFinding[];
}

export function SecurityFindingsPanel({
  snykVulnerabilities,
  semgrepFindings,
}: SecurityFindingsPanelProps) {
  // Group vulnerabilities by severity
  const groupedVulns = {
    critical: snykVulnerabilities.filter((v) => v.severity === "critical"),
    high: snykVulnerabilities.filter((v) => v.severity === "high"),
    medium: snykVulnerabilities.filter((v) => v.severity === "medium"),
    low: snykVulnerabilities.filter((v) => v.severity === "low"),
  };

  return (
    <div className="space-y-4">
      {/* Snyk Vulnerabilities */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="rounded-xl border border-border bg-card"
      >
        <div className="flex items-center gap-3 border-b border-border px-4 py-3">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-destructive/10">
            <Shield className="h-4 w-4 text-destructive" />
          </div>
          <div className="flex-1">
            <h3 className="font-semibold text-foreground">
              Snyk Vulnerabilities
            </h3>
            <p className="text-xs text-muted-foreground">
              {snykVulnerabilities.length} issues found
            </p>
          </div>
        </div>

        <div className="p-4 space-y-3">
          {(["critical", "high", "medium", "low"] as RiskLevel[]).map(
            (severity) => {
              const vulns = groupedVulns[severity];
              if (vulns.length === 0) return null;

              return (
                <SeverityGroup
                  key={severity}
                  severity={severity}
                  count={vulns.length}
                >
                  {vulns.map((vuln) => (
                    <VulnerabilityCard key={vuln.id} vulnerability={vuln} />
                  ))}
                </SeverityGroup>
              );
            }
          )}

          {snykVulnerabilities.length === 0 && (
            <div className="py-8 text-center">
              <Shield className="mx-auto h-8 w-8 text-success" />
              <p className="mt-2 text-sm text-muted-foreground">
                No vulnerabilities detected
              </p>
            </div>
          )}
        </div>
      </motion.div>

      {/* Semgrep Findings */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="rounded-xl border border-border bg-card"
      >
        <div className="flex items-center gap-3 border-b border-border px-4 py-3">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-warning/10">
            <Bug className="h-4 w-4 text-warning" />
          </div>
          <div className="flex-1">
            <h3 className="font-semibold text-foreground">Semgrep Findings</h3>
            <p className="text-xs text-muted-foreground">
              {semgrepFindings.length} issues found
            </p>
          </div>
        </div>

        <div className="p-4 space-y-3">
          {semgrepFindings.map((finding, index) => (
            <SemgrepFindingCard key={finding.id} finding={finding} index={index} />
          ))}

          {semgrepFindings.length === 0 && (
            <div className="py-8 text-center">
              <Bug className="mx-auto h-8 w-8 text-success" />
              <p className="mt-2 text-sm text-muted-foreground">
                No security issues detected
              </p>
            </div>
          )}
        </div>
      </motion.div>
    </div>
  );
}

function SeverityGroup({
  severity,
  count,
  children,
}: {
  severity: RiskLevel;
  count: number;
  children: React.ReactNode;
}) {
  const [isOpen, setIsOpen] = useState(severity === "critical" || severity === "high");

  return (
    <Collapsible open={isOpen} onOpenChange={setIsOpen}>
      <CollapsibleTrigger className="flex w-full items-center gap-2 rounded-lg bg-muted/30 px-3 py-2 transition-colors hover:bg-muted/50">
        {isOpen ? (
          <ChevronDown className="h-4 w-4 text-muted-foreground" />
        ) : (
          <ChevronRight className="h-4 w-4 text-muted-foreground" />
        )}
        <RiskLevelBadge level={severity} size="sm" />
        <span className="flex-1 text-left text-sm font-medium text-foreground">
          {count} {severity} {count === 1 ? "issue" : "issues"}
        </span>
      </CollapsibleTrigger>
      <CollapsibleContent>
        <div className="mt-2 space-y-2 pl-6">{children}</div>
      </CollapsibleContent>
    </Collapsible>
  );
}

function VulnerabilityCard({ vulnerability }: { vulnerability: Vulnerability }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <motion.div
      className="rounded-lg border border-border bg-muted/20 p-3 transition-colors hover:bg-muted/30"
      whileHover={{ scale: 1.01 }}
    >
      <button
        type="button"
        onClick={() => setExpanded(!expanded)}
        className="flex w-full items-start gap-3 text-left"
      >
        <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-warning" />
        <div className="flex-1 min-w-0">
          <h4 className="text-sm font-medium text-foreground">
            {vulnerability.title}
          </h4>
          <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
            {vulnerability.package && (
              <span className="font-mono">{vulnerability.package}</span>
            )}
            {vulnerability.cwe && (
              <Badge variant="outline" className="text-xs">
                {vulnerability.cwe}
              </Badge>
            )}
            {vulnerability.cvss && (
              <TooltipProvider>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Badge variant="outline" className="text-xs">
                      CVSS: {vulnerability.cvss}
                    </Badge>
                  </TooltipTrigger>
                  <TooltipContent>
                    Common Vulnerability Scoring System
                  </TooltipContent>
                </Tooltip>
              </TooltipProvider>
            )}
          </div>
        </div>
        {expanded ? (
          <ChevronDown className="h-4 w-4 shrink-0 text-muted-foreground" />
        ) : (
          <ChevronRight className="h-4 w-4 shrink-0 text-muted-foreground" />
        )}
      </button>

      <AnimatePresence>
        {expanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="mt-3 overflow-hidden"
          >
            <p className="text-sm text-muted-foreground">
              {vulnerability.description}
            </p>
            {vulnerability.fixedVersion && (
              <div className="mt-2 flex items-center gap-2 rounded-lg bg-success/10 px-3 py-2 text-xs">
                <Info className="h-3 w-3 text-success" />
                <span className="text-success">
                  Fix available: Upgrade to v{vulnerability.fixedVersion}
                </span>
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

function SemgrepFindingCard({
  finding,
  index,
}: {
  finding: SemgrepFinding;
  index: number;
}) {
  const [expanded, setExpanded] = useState(false);

  return (
    <motion.div
      initial={{ opacity: 0, x: -20 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: index * 0.05 }}
      className="rounded-lg border border-border bg-muted/20 p-3 transition-colors hover:bg-muted/30"
    >
      <button
        type="button"
        onClick={() => setExpanded(!expanded)}
        className="flex w-full items-start gap-3 text-left"
      >
        <FileCode className="mt-0.5 h-4 w-4 shrink-0 text-primary" />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <h4 className="text-sm font-medium text-foreground">
              {finding.message}
            </h4>
            <RiskLevelBadge level={finding.severity} size="sm" />
          </div>
          <div className="mt-1 flex items-center gap-2 text-xs text-muted-foreground">
            <span className="font-mono">{finding.ruleId}</span>
            <span>|</span>
            <span>{finding.path}</span>
            <span>:</span>
            <span>
              L{finding.startLine}
              {finding.endLine !== finding.startLine && `-${finding.endLine}`}
            </span>
          </div>
        </div>
        {expanded ? (
          <ChevronDown className="h-4 w-4 shrink-0 text-muted-foreground" />
        ) : (
          <ChevronRight className="h-4 w-4 shrink-0 text-muted-foreground" />
        )}
      </button>

      <AnimatePresence>
        {expanded && finding.snippet && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="mt-3 overflow-hidden"
          >
            <pre className="rounded-lg bg-background/50 p-3 font-mono text-xs text-foreground overflow-x-auto">
              {finding.snippet}
            </pre>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}
