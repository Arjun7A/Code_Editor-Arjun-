"use client";

import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Brain,
  Lightbulb,
  AlertCircle,
  ChevronDown,
  ChevronRight,
  Sparkles,
  Shield,
  Zap,
  Code,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { cn } from "@/lib/utils";
import type { AIFinding } from "@/lib/types";

interface AIAnalysisSectionProps {
  findings: AIFinding[];
}

const typeConfig = {
  security: {
    icon: Shield,
    label: "Security",
    color: "text-destructive",
    bgColor: "bg-destructive/10",
  },
  logic: {
    icon: Code,
    label: "Logic",
    color: "text-warning",
    bgColor: "bg-warning/10",
  },
  performance: {
    icon: Zap,
    label: "Performance",
    color: "text-info",
    bgColor: "bg-info/10",
  },
  best_practice: {
    icon: Sparkles,
    label: "Best Practice",
    color: "text-accent",
    bgColor: "bg-accent/10",
  },
};

export function AIAnalysisSection({ findings }: AIAnalysisSectionProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="rounded-xl border border-border bg-card"
    >
      {/* Header */}
      <div className="flex items-center gap-3 border-b border-border px-4 py-3">
        <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary/10">
          <Brain className="h-4 w-4 text-primary" />
        </div>
        <div className="flex-1">
          <h3 className="font-semibold text-foreground">LangChain AI Analysis</h3>
          <p className="text-xs text-muted-foreground">
            AI-powered code intelligence and recommendations
          </p>
        </div>
        <Badge className="bg-primary/10 text-primary">
          {findings.length} findings
        </Badge>
      </div>

      {/* Findings */}
      <div className="p-4 space-y-3">
        {findings.map((finding, index) => (
          <AIFindingCard key={finding.id} finding={finding} index={index} />
        ))}

        {findings.length === 0 && (
          <div className="py-8 text-center">
            <Brain className="mx-auto h-8 w-8 text-success" />
            <p className="mt-2 text-sm text-muted-foreground">
              No concerns identified by AI analysis
            </p>
          </div>
        )}
      </div>
    </motion.div>
  );
}

function AIFindingCard({
  finding,
  index,
}: {
  finding: AIFinding;
  index: number;
}) {
  const [expanded, setExpanded] = useState(false);
  const config = typeConfig[finding.type];
  const Icon = config.icon;

  return (
    <motion.div
      initial={{ opacity: 0, x: -20 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: index * 0.1 }}
      className="rounded-lg border border-border bg-muted/20 overflow-hidden"
    >
      <button
        type="button"
        onClick={() => setExpanded(!expanded)}
        className="flex w-full items-start gap-3 p-4 text-left transition-colors hover:bg-muted/30"
      >
        <div className={cn("mt-0.5 rounded-lg p-2", config.bgColor)}>
          <Icon className={cn("h-4 w-4", config.color)} />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <h4 className="text-sm font-medium text-foreground">
              {finding.title}
            </h4>
            <Badge variant="outline" className={cn("text-xs", config.color)}>
              {config.label}
            </Badge>
          </div>
          <p className="mt-1 line-clamp-2 text-sm text-muted-foreground">
            {finding.description}
          </p>

          {/* Confidence Score */}
          <div className="mt-3 flex items-center gap-3">
            <span className="text-xs text-muted-foreground">Confidence:</span>
            <Progress
              value={finding.confidence * 100}
              className="h-2 w-24"
            />
            <span className="text-xs font-medium text-foreground">
              {Math.round(finding.confidence * 100)}%
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
        {expanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="overflow-hidden"
          >
            <div className="border-t border-border bg-muted/10 px-4 py-4">
              {/* Recommendation */}
              <div className="flex items-start gap-3 rounded-lg bg-success/10 p-3">
                <Lightbulb className="mt-0.5 h-4 w-4 shrink-0 text-success" />
                <div>
                  <h5 className="text-xs font-semibold uppercase tracking-wider text-success">
                    Recommendation
                  </h5>
                  <p className="mt-1 text-sm text-foreground">
                    {finding.recommendation}
                  </p>
                </div>
              </div>

              {/* Affected Code */}
              {finding.affectedCode && (
                <div className="mt-3">
                  <h5 className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                    <AlertCircle className="h-3 w-3" />
                    Affected Code
                  </h5>
                  <pre className="mt-2 overflow-x-auto rounded-lg bg-background/50 p-3 font-mono text-xs text-foreground">
                    {finding.affectedCode}
                  </pre>
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}
