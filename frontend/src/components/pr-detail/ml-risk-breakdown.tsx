"use client";

import { motion } from "framer-motion";
import { Cpu, TrendingUp, TrendingDown, Info } from "lucide-react";
import { Progress } from "@/components/ui/progress";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { RiskGauge } from "@/components/ui/risk-gauge";
import { cn } from "@/lib/utils";
import type { MLRiskFactor } from "@/lib/types";

interface MLRiskBreakdownProps {
  riskScore: number;
  factors: MLRiskFactor[];
}

export function MLRiskBreakdown({ riskScore, factors }: MLRiskBreakdownProps) {
  // Sort factors by absolute contribution
  const sortedFactors = [...factors].sort(
    (a, b) => Math.abs(b.contribution) - Math.abs(a.contribution)
  );

  const totalPositive = factors
    .filter((f) => f.contribution > 0)
    .reduce((sum, f) => sum + f.contribution, 0);
  const totalNegative = Math.abs(
    factors.filter((f) => f.contribution < 0).reduce((sum, f) => sum + f.contribution, 0)
  );

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="rounded-xl border border-border bg-card"
    >
      {/* Header */}
      <div className="flex items-center gap-3 border-b border-border px-4 py-3">
        <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-info/10">
          <Cpu className="h-4 w-4 text-info" />
        </div>
        <div className="flex-1">
          <h3 className="font-semibold text-foreground">ML Risk Analysis</h3>
          <p className="text-xs text-muted-foreground">
            Explainable AI risk scoring model
          </p>
        </div>
      </div>

      <div className="p-4">
        {/* Risk Score Visualization */}
        <div className="mb-6 flex items-center justify-center">
          <RiskGauge score={riskScore} size="lg" />
        </div>

        {/* Summary Stats */}
        <div className="mb-6 grid grid-cols-2 gap-4">
          <div className="rounded-lg bg-destructive/10 p-3 text-center">
            <div className="flex items-center justify-center gap-1 text-destructive">
              <TrendingUp className="h-4 w-4" />
              <span className="text-lg font-bold">+{totalPositive}</span>
            </div>
            <p className="mt-1 text-xs text-muted-foreground">Risk Factors</p>
          </div>
          <div className="rounded-lg bg-success/10 p-3 text-center">
            <div className="flex items-center justify-center gap-1 text-success">
              <TrendingDown className="h-4 w-4" />
              <span className="text-lg font-bold">-{totalNegative}</span>
            </div>
            <p className="mt-1 text-xs text-muted-foreground">Mitigating Factors</p>
          </div>
        </div>

        {/* Factor Breakdown */}
        <div className="space-y-4">
          <h4 className="flex items-center gap-2 text-sm font-semibold text-foreground">
            <Info className="h-4 w-4 text-muted-foreground" />
            Feature Contributions
          </h4>

          {sortedFactors.map((factor, index) => (
            <RiskFactorBar key={factor.name} factor={factor} index={index} />
          ))}
        </div>

        {/* Explanation */}
        <div className="mt-6 rounded-lg bg-muted/30 p-4">
          <h5 className="text-sm font-semibold text-foreground">
            Why This Score?
          </h5>
          <p className="mt-2 text-sm text-muted-foreground">
            The ML model analyzes {factors.length} key features to determine risk.
            This PR has significant contributions from{" "}
            <span className="font-medium text-foreground">
              {sortedFactors[0]?.name}
            </span>{" "}
            ({sortedFactors[0]?.contribution > 0 ? "+" : ""}
            {sortedFactors[0]?.contribution}) and{" "}
            <span className="font-medium text-foreground">
              {sortedFactors[1]?.name}
            </span>{" "}
            ({sortedFactors[1]?.contribution > 0 ? "+" : ""}
            {sortedFactors[1]?.contribution}).
          </p>
        </div>
      </div>
    </motion.div>
  );
}

function RiskFactorBar({
  factor,
  index,
}: {
  factor: MLRiskFactor;
  index: number;
}) {
  const isPositive = factor.contribution > 0;
  const absContribution = Math.abs(factor.contribution);
  const maxContribution = 50; // Max for visualization

  return (
    <TooltipProvider>
      <Tooltip>
        <TooltipTrigger asChild>
          <motion.div
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: index * 0.05 }}
            className="cursor-help"
          >
            <div className="flex items-center justify-between text-sm">
              <span className="text-muted-foreground">{factor.name}</span>
              <span
                className={cn(
                  "font-medium",
                  isPositive ? "text-destructive" : "text-success"
                )}
              >
                {isPositive ? "+" : ""}
                {factor.contribution}
              </span>
            </div>
            <div className="mt-1.5 flex items-center gap-2">
              {/* Negative bar (left side) */}
              <div className="flex h-2 w-1/2 justify-end rounded-l-full bg-muted/30">
                {!isPositive && (
                  <motion.div
                    className="h-full rounded-l-full bg-success"
                    initial={{ width: 0 }}
                    animate={{
                      width: `${(absContribution / maxContribution) * 100}%`,
                    }}
                    transition={{ duration: 0.5, delay: index * 0.05 }}
                  />
                )}
              </div>
              {/* Center line */}
              <div className="h-3 w-0.5 bg-border" />
              {/* Positive bar (right side) */}
              <div className="flex h-2 w-1/2 rounded-r-full bg-muted/30">
                {isPositive && (
                  <motion.div
                    className="h-full rounded-r-full bg-destructive"
                    initial={{ width: 0 }}
                    animate={{
                      width: `${(absContribution / maxContribution) * 100}%`,
                    }}
                    transition={{ duration: 0.5, delay: index * 0.05 }}
                  />
                )}
              </div>
            </div>
          </motion.div>
        </TooltipTrigger>
        <TooltipContent side="top" className="max-w-xs">
          <p className="font-medium">{factor.name}</p>
          <p className="text-muted-foreground">{factor.description}</p>
          <div className="mt-2 text-xs">
            <span>Value: {factor.value}</span>
            <span className="mx-2">|</span>
            <span>Weight: {(factor.weight * 100).toFixed(0)}%</span>
          </div>
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}
