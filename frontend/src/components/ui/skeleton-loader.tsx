"use client";

import { motion } from "framer-motion";
import { cn } from "@/lib/utils";

interface SkeletonProps {
  className?: string;
}

export function Skeleton({ className }: SkeletonProps) {
  return (
    <motion.div
      className={cn(
        "rounded-md bg-muted/50",
        className
      )}
      animate={{
        opacity: [0.5, 1, 0.5],
      }}
      transition={{
        duration: 1.5,
        repeat: Infinity,
        ease: "easeInOut",
      }}
    />
  );
}

export function StatCardSkeleton() {
  return (
    <div className="rounded-xl border border-border bg-card p-6">
      <div className="flex items-center justify-between">
        <Skeleton className="h-4 w-24" />
        <Skeleton className="h-8 w-8 rounded-lg" />
      </div>
      <Skeleton className="mt-4 h-8 w-20" />
      <Skeleton className="mt-2 h-3 w-32" />
    </div>
  );
}

export function PRCardSkeleton() {
  return (
    <div className="rounded-xl border border-border bg-card p-4">
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-3">
          <Skeleton className="h-10 w-10 rounded-full" />
          <div>
            <Skeleton className="h-4 w-32" />
            <Skeleton className="mt-1 h-3 w-24" />
          </div>
        </div>
        <Skeleton className="h-6 w-20 rounded-full" />
      </div>
      <Skeleton className="mt-4 h-4 w-full" />
      <div className="mt-4 flex items-center justify-between">
        <Skeleton className="h-3 w-20" />
        <Skeleton className="h-8 w-16 rounded-lg" />
      </div>
    </div>
  );
}

export function TableRowSkeleton() {
  return (
    <div className="flex items-center gap-4 border-b border-border px-4 py-3">
      <Skeleton className="h-4 w-16" />
      <Skeleton className="h-4 w-32" />
      <Skeleton className="h-4 w-24" />
      <Skeleton className="h-6 w-20 rounded-full" />
      <Skeleton className="h-4 w-12" />
      <Skeleton className="h-4 w-28" />
    </div>
  );
}

export function ChartSkeleton() {
  return (
    <div className="h-64 rounded-xl border border-border bg-card p-4">
      <Skeleton className="h-4 w-32" />
      <div className="mt-4 flex h-48 items-end justify-around gap-2">
        {Array.from({ length: 8 }).map((_, i) => (
          <Skeleton
            key={i}
            className="w-8 rounded-t"
            style={{ height: `${Math.random() * 100 + 40}px` }}
          />
        ))}
      </div>
    </div>
  );
}

export function CodeDiffSkeleton() {
  return (
    <div className="rounded-xl border border-border bg-card">
      <div className="border-b border-border px-4 py-3">
        <Skeleton className="h-4 w-48" />
      </div>
      <div className="p-4 font-mono text-sm">
        {Array.from({ length: 10 }).map((_, i) => (
          <div key={i} className="flex gap-4 py-1">
            <Skeleton className="h-4 w-8" />
            <Skeleton className="h-4" style={{ width: `${Math.random() * 60 + 20}%` }} />
          </div>
        ))}
      </div>
    </div>
  );
}

export function FindingCardSkeleton() {
  return (
    <div className="rounded-xl border border-border bg-card p-4">
      <div className="flex items-start justify-between">
        <Skeleton className="h-5 w-48" />
        <Skeleton className="h-6 w-16 rounded-full" />
      </div>
      <Skeleton className="mt-3 h-4 w-full" />
      <Skeleton className="mt-2 h-4 w-3/4" />
      <div className="mt-4 flex items-center gap-4">
        <Skeleton className="h-3 w-24" />
        <Skeleton className="h-3 w-20" />
      </div>
    </div>
  );
}
