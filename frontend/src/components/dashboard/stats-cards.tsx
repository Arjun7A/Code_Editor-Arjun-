"use client";

import { motion } from "framer-motion";
import {
  GitPullRequest,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  TrendingUp,
  Shield,
  Activity,
} from "lucide-react";
import { AnimatedCounter } from "@/components/ui/animated-counter";
import { StatCardSkeleton } from "@/components/ui/skeleton-loader";
import type { DashboardStats } from "@/lib/types";
import { cn } from "@/lib/utils";

interface StatsCardsProps {
  stats: DashboardStats | null;
  loading?: boolean;
}

const cardVariants = {
  hidden: { opacity: 0, y: 20 },
  visible: (i: number) => ({
    opacity: 1,
    y: 0,
    transition: {
      delay: i * 0.1,
      duration: 0.5,
      ease: [0.4, 0, 0.2, 1] as any,
    },
  }),
};

export function StatsCards({ stats, loading }: StatsCardsProps) {
  if (loading || !stats) {
    return (
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {Array.from({ length: 7 }).map((_, i) => (
          <StatCardSkeleton key={i} />
        ))}
      </div>
    );
  }

  const cards = [
    {
      title: "Total PRs Analyzed",
      value: stats.totalPRs,
      icon: GitPullRequest,
      color: "text-primary",
      bgColor: "bg-primary/10",
      trend: "+12.5%",
      trendUp: true,
    },
    {
      title: "Approved",
      value: stats.approved,
      icon: CheckCircle2,
      color: "text-success",
      bgColor: "bg-success/10",
      trend: "+8.2%",
      trendUp: true,
    },
    {
      title: "Blocked",
      value: stats.blocked,
      icon: XCircle,
      color: "text-destructive",
      bgColor: "bg-destructive/10",
      trend: "-3.1%",
      trendUp: false,
    },
    {
      title: "Manual Review",
      value: stats.manualReview,
      icon: AlertTriangle,
      color: "text-warning",
      bgColor: "bg-warning/10",
      trend: "+2.4%",
      trendUp: true,
    },
    {
      title: "Avg Risk Score",
      value: stats.avgRiskScore,
      icon: TrendingUp,
      color: "text-info",
      bgColor: "bg-info/10",
      formatFn: (v: number) => v.toFixed(1),
      suffix: "%",
    },
    {
      title: "Critical Issues",
      value: stats.criticalIssues,
      icon: Shield,
      color: "text-critical",
      bgColor: "bg-critical/10",
      trend: "-15.2%",
      trendUp: false,
    },
    {
      title: "Scans Today",
      value: stats.scansTodayAmount,
      icon: Activity,
      color: "text-accent",
      bgColor: "bg-accent/10",
    },
  ];

  return (
    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4 xl:grid-cols-7">
      {cards.map((card, index) => {
        const Icon = card.icon;
        return (
          <motion.div
            key={card.title}
            custom={index}
            initial="hidden"
            animate="visible"
            variants={cardVariants}
            whileHover={{ scale: 1.02, transition: { duration: 0.2 } }}
            className="group relative overflow-hidden rounded-xl border border-border bg-card p-5 transition-colors hover:border-primary/30"
          >
            {/* Glow effect on hover */}
            <div className="pointer-events-none absolute inset-0 opacity-0 transition-opacity duration-300 group-hover:opacity-100">
              <div
                className={cn(
                  "absolute -right-4 -top-4 h-24 w-24 rounded-full blur-2xl",
                  card.bgColor
                )}
              />
            </div>

            <div className="relative">
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium text-muted-foreground">
                  {card.title}
                </span>
                <div className={cn("rounded-lg p-2", card.bgColor)}>
                  <Icon className={cn("h-4 w-4", card.color)} />
                </div>
              </div>

              <div className="mt-3 flex items-baseline gap-2">
                <AnimatedCounter
                  value={card.value}
                  className="text-2xl font-bold text-foreground"
                  formatFn={card.formatFn}
                />
                {card.suffix && (
                  <span className="text-lg font-semibold text-muted-foreground">
                    {card.suffix}
                  </span>
                )}
              </div>

              {card.trend && (
                <div className="mt-2 flex items-center gap-1">
                  <span
                    className={cn(
                      "text-xs font-medium",
                      card.trendUp ? "text-success" : "text-destructive"
                    )}
                  >
                    {card.trend}
                  </span>
                  <span className="text-xs text-muted-foreground">
                    vs last month
                  </span>
                </div>
              )}
            </div>
          </motion.div>
        );
      })}
    </div>
  );
}
