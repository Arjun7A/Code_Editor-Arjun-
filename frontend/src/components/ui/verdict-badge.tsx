"use client";

import { motion } from "framer-motion";
import { AlertTriangle, CheckCircle2, ShieldAlert } from "lucide-react";
import { cn } from "@/lib/utils";
import type { RiskLevel, Verdict } from "@/lib/types";

interface VerdictBadgeProps {
  verdict: Verdict;
  size?: "sm" | "md" | "lg";
  showIcon?: boolean;
  animated?: boolean;
  className?: string;
}

const verdictConfig = {
  clean: {
    label: "Clean",
    icon: CheckCircle2,
    color: "#22c55e",
  },
  issues_found: {
    label: "Issues Found",
    icon: AlertTriangle,
    color: "#eab308",
  },
  critical: {
    label: "Critical",
    icon: ShieldAlert,
    color: "#ef4444",
  },
} as const;

const riskLevelConfig = {
  critical: { label: "CRITICAL", color: "#ef4444" },
  high: { label: "HIGH", color: "#f97316" },
  medium: { label: "MEDIUM", color: "#eab308" },
  low: { label: "LOW", color: "#3b82f6" },
} as const;

const sizeConfig = {
  sm: "px-2 py-0.5 text-xs gap-1",
  md: "px-3 py-1 text-sm gap-1.5",
  lg: "px-4 py-1.5 text-base gap-2",
};

const iconSizeConfig = {
  sm: "h-3 w-3",
  md: "h-4 w-4",
  lg: "h-5 w-5",
};

function hexToRgba(hex: string, alpha: number) {
  const normalized = hex.replace("#", "");
  const red = Number.parseInt(normalized.slice(0, 2), 16);
  const green = Number.parseInt(normalized.slice(2, 4), 16);
  const blue = Number.parseInt(normalized.slice(4, 6), 16);
  return `rgba(${red}, ${green}, ${blue}, ${alpha})`;
}

export function VerdictBadge({
  verdict,
  size = "md",
  showIcon = true,
  animated = true,
  className,
}: VerdictBadgeProps) {
  const config = verdictConfig[verdict];
  const Icon = config.icon;

  const badge = (
    <span
      className={cn(
        "inline-flex items-center rounded-full border font-medium",
        sizeConfig[size],
        className
      )}
      style={{
        color: config.color,
        backgroundColor: hexToRgba(config.color, 0.16),
        borderColor: hexToRgba(config.color, 0.35),
      }}
    >
      {showIcon ? <Icon className={iconSizeConfig[size]} /> : null}
      {config.label}
    </span>
  );

  if (!animated) {
    return badge;
  }

  return (
    <motion.div initial={{ opacity: 0, scale: 0.92 }} animate={{ opacity: 1, scale: 1 }}>
      {badge}
    </motion.div>
  );
}

interface RiskLevelBadgeProps {
  level: RiskLevel;
  size?: "sm" | "md" | "lg";
  className?: string;
}

export function RiskLevelBadge({
  level,
  size = "md",
  className,
}: RiskLevelBadgeProps) {
  const config = riskLevelConfig[level];

  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full border font-medium",
        sizeConfig[size],
        className
      )}
      style={{
        color: config.color,
        backgroundColor: hexToRgba(config.color, 0.16),
        borderColor: hexToRgba(config.color, 0.35),
      }}
    >
      {config.label}
    </span>
  );
}
