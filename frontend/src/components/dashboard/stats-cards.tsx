"use client";

import { motion } from "framer-motion";
import { Activity, ShieldAlert } from "lucide-react";
import { AnimatedCounter } from "@/components/ui/animated-counter";
import { StatCardSkeleton } from "@/components/ui/skeleton-loader";
import type { DashboardStats } from "@/lib/types";

interface StatsCardsProps {
  stats: DashboardStats | null;
  loading?: boolean;
}

const cards = [
  {
    key: "totalScans",
    label: "Total Scans",
    icon: Activity,
    accent: "bg-primary/15 text-primary",
  },
  {
    key: "totalIssues",
    label: "Total Issues",
    icon: ShieldAlert,
    accent: "bg-destructive/15 text-destructive",
  },
] as const;

export function StatsCards({ stats, loading }: StatsCardsProps) {
  if (loading) {
    return (
      <div className="grid gap-4 md:grid-cols-2">
        {cards.map((card) => (
          <StatCardSkeleton key={card.key} />
        ))}
      </div>
    );
  }

  if (!stats) {
    return (
      <div className="rounded-xl border border-border/60 bg-card/70 p-5 text-sm text-muted-foreground">
        Dashboard stats will appear here once the backend responds.
      </div>
    );
  }

  return (
    <div className="grid gap-4 md:grid-cols-2">
      {cards.map((card, index) => {
        const Icon = card.icon;
        const value = stats[card.key];

        return (
          <motion.div
            key={card.key}
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: index * 0.08 }}
            className="rounded-xl border border-border/60 bg-card/80 p-5"
          >
            <div className="flex items-start justify-between gap-4">
              <div>
                <p className="text-sm text-muted-foreground">{card.label}</p>
                <div className="mt-3 text-3xl font-semibold text-foreground">
                  <AnimatedCounter value={value} />
                </div>
              </div>

              <div className={`rounded-xl p-3 ${card.accent}`}>
                <Icon className="h-5 w-5" />
              </div>
            </div>
          </motion.div>
        );
      })}
    </div>
  );
}
