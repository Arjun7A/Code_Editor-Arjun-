"use client";

import { motion } from "framer-motion";
import { CheckCircle2, XCircle, AlertTriangle } from "lucide-react";
import { cn } from "@/lib/utils";
import type { Verdict, RiskLevel } from "@/lib/types";

interface VerdictBadgeProps {
  verdict: Verdict;
  size?: "sm" | "md" | "lg";
  showIcon?: boolean;
  animated?: boolean;
  className?: string;
}

const verdictConfig = {
  approved: {
    label: "Approved",
    icon: CheckCircle2,
    bgClass: "bg-success/15",
    textClass: "text-success",
    borderClass: "border-success/30",
  },
  blocked: {
    label: "Blocked",
    icon: XCircle,
    bgClass: "bg-destructive/15",
    textClass: "text-destructive",
    borderClass: "border-destructive/30",
  },
  manual_review: {
    label: "Manual Review",
    icon: AlertTriangle,
    bgClass: "bg-warning/15",
    textClass: "text-warning",
    borderClass: "border-warning/30",
  },
};

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
        config.bgClass,
        config.textClass,
        config.borderClass,
        sizeConfig[size],
        className
      )}
    >
      {showIcon && <Icon className={iconSizeConfig[size]} />}
      {config.label}
    </span>
  );

  if (animated) {
    return (
      <motion.div
        initial={{ opacity: 0, scale: 0.8 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ duration: 0.3 }}
      >
        {badge}
      </motion.div>
    );
  }

  return badge;
}

// Risk Level Badge
interface RiskLevelBadgeProps {
  level: RiskLevel;
  size?: "sm" | "md" | "lg";
  className?: string;
}

const riskLevelConfig = {
  critical: {
    label: "Critical",
    bgClass: "bg-critical/15",
    textClass: "text-critical",
    borderClass: "border-critical/30",
  },
  high: {
    label: "High",
    bgClass: "bg-destructive/15",
    textClass: "text-destructive",
    borderClass: "border-destructive/30",
  },
  medium: {
    label: "Medium",
    bgClass: "bg-warning/15",
    textClass: "text-warning",
    borderClass: "border-warning/30",
  },
  low: {
    label: "Low",
    bgClass: "bg-success/15",
    textClass: "text-success",
    borderClass: "border-success/30",
  },
};

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
        config.bgClass,
        config.textClass,
        config.borderClass,
        sizeConfig[size],
        className
      )}
    >
      {config.label}
    </span>
  );
}
