"use client";

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { cn } from "@/lib/utils";
import type { RiskLevel } from "@/lib/types";

interface RiskGaugeProps {
  score: number;
  size?: "sm" | "md" | "lg";
  showLabel?: boolean;
  className?: string;
}

const sizeConfig = {
  sm: { width: 60, height: 60, strokeWidth: 4, fontSize: "text-sm" },
  md: { width: 100, height: 100, strokeWidth: 6, fontSize: "text-xl" },
  lg: { width: 140, height: 140, strokeWidth: 8, fontSize: "text-3xl" },
};

function getRiskLevel(score: number): RiskLevel {
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 40) return "medium";
  return "low";
}

function getRiskColor(score: number): string {
  const level = getRiskLevel(score);
  switch (level) {
    case "critical":
      return "stroke-critical";
    case "high":
      return "stroke-destructive";
    case "medium":
      return "stroke-warning";
    case "low":
      return "stroke-success";
  }
}

function getRiskBgColor(score: number): string {
  const level = getRiskLevel(score);
  switch (level) {
    case "critical":
      return "text-critical";
    case "high":
      return "text-destructive";
    case "medium":
      return "text-warning";
    case "low":
      return "text-success";
  }
}

export function RiskGauge({
  score,
  size = "md",
  showLabel = true,
  className,
}: RiskGaugeProps) {
  const [mounted, setMounted] = useState(false);
  const config = sizeConfig[size];
  const radius = (config.width - config.strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const progress = (score / 100) * circumference;

  useEffect(() => {
    setMounted(true);
  }, []);

  return (
    <div className={cn("relative inline-flex items-center justify-center", className)}>
      <svg
        width={config.width}
        height={config.height}
        className="-rotate-90 transform"
      >
        {/* Background circle */}
        <circle
          cx={config.width / 2}
          cy={config.height / 2}
          r={radius}
          fill="none"
          stroke="currentColor"
          strokeWidth={config.strokeWidth}
          className="text-muted/30"
        />
        {/* Progress circle */}
        <motion.circle
          cx={config.width / 2}
          cy={config.height / 2}
          r={radius}
          fill="none"
          strokeWidth={config.strokeWidth}
          strokeLinecap="round"
          className={getRiskColor(score)}
          strokeDasharray={circumference}
          initial={{ strokeDashoffset: circumference }}
          animate={{
            strokeDashoffset: mounted ? circumference - progress : circumference,
          }}
          transition={{ duration: 1, ease: "easeOut" }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <motion.span
          className={cn("font-bold", config.fontSize, getRiskBgColor(score))}
          initial={{ opacity: 0, scale: 0.5 }}
          animate={{ opacity: mounted ? 1 : 0, scale: mounted ? 1 : 0.5 }}
          transition={{ duration: 0.5, delay: 0.3 }}
        >
          {score}
        </motion.span>
        {showLabel && size !== "sm" && (
          <motion.span
            className="text-xs text-muted-foreground"
            initial={{ opacity: 0 }}
            animate={{ opacity: mounted ? 1 : 0 }}
            transition={{ duration: 0.5, delay: 0.5 }}
          >
            Risk Score
          </motion.span>
        )}
      </div>
    </div>
  );
}

// Linear progress bar variant
interface RiskBarProps {
  score: number;
  className?: string;
  showLabel?: boolean;
}

export function RiskBar({ score, className, showLabel = true }: RiskBarProps) {
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  const level = getRiskLevel(score);
  const bgColor =
    level === "critical"
      ? "bg-critical"
      : level === "high"
        ? "bg-destructive"
        : level === "medium"
          ? "bg-warning"
          : "bg-success";

  return (
    <div className={cn("w-full", className)}>
      {showLabel && (
        <div className="mb-1 flex items-center justify-between text-sm">
          <span className="text-muted-foreground">Risk Score</span>
          <span className={cn("font-medium", getRiskBgColor(score))}>{score}%</span>
        </div>
      )}
      <div className="h-2 w-full overflow-hidden rounded-full bg-muted/30">
        <motion.div
          className={cn("h-full rounded-full", bgColor)}
          initial={{ width: 0 }}
          animate={{ width: mounted ? `${score}%` : 0 }}
          transition={{ duration: 1, ease: "easeOut" }}
        />
      </div>
    </div>
  );
}
