"use client";

import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  ChevronLeft,
  ChevronRight,
  GitBranch,
  Filter,
  Folder,
  CheckCircle2,
  XCircle,
  AlertTriangle,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { cn } from "@/lib/utils";

interface Repository {
  id: string;
  name: string;
  owner: string;
  prCount: number;
}

const mockRepos: Repository[] = [
  { id: "1", name: "api-gateway", owner: "acme-corp", prCount: 12 },
  { id: "2", name: "web-app", owner: "acme-corp", prCount: 8 },
  { id: "3", name: "auth-service", owner: "acme-corp", prCount: 5 },
  { id: "4", name: "payment-service", owner: "acme-corp", prCount: 3 },
  { id: "5", name: "notification-hub", owner: "acme-corp", prCount: 2 },
];

interface SidebarProps {
  onFilterChange?: (filter: string) => void;
  onRepoSelect?: (repoId: string) => void;
  selectedRepo?: string;
  selectedFilter?: string;
}

export function Sidebar({
  onFilterChange,
  onRepoSelect,
  selectedRepo = "all",
  selectedFilter = "all",
}: SidebarProps) {
  const [collapsed, setCollapsed] = useState(false);

  const filters = [
    {
      id: "all",
      label: "All PRs",
      icon: GitBranch,
      count: 30,
    },
    {
      id: "approved",
      label: "Approved",
      icon: CheckCircle2,
      count: 18,
      color: "text-success",
    },
    {
      id: "blocked",
      label: "Blocked",
      icon: XCircle,
      count: 5,
      color: "text-destructive",
    },
    {
      id: "manual_review",
      label: "Manual Review",
      icon: AlertTriangle,
      count: 7,
      color: "text-warning",
    },
  ];

  return (
    <motion.aside
      className="relative hidden h-[calc(100vh-4rem)] border-r border-border bg-sidebar lg:block"
      animate={{ width: collapsed ? 64 : 256 }}
      transition={{ duration: 0.2, ease: "easeInOut" }}
    >
      {/* Collapse Toggle */}
      <Button
        variant="ghost"
        size="icon"
        className="absolute -right-3 top-6 z-10 h-6 w-6 rounded-full border border-border bg-background shadow-sm"
        onClick={() => setCollapsed(!collapsed)}
      >
        {collapsed ? (
          <ChevronRight className="h-3 w-3" />
        ) : (
          <ChevronLeft className="h-3 w-3" />
        )}
      </Button>

      <ScrollArea className="h-full py-4">
        <div className={cn("px-3", collapsed && "px-2")}>
          {/* Quick Filters */}
          <div className="mb-4">
            <AnimatePresence>
              {!collapsed && (
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  className="mb-2 flex items-center gap-2 px-2 text-xs font-medium uppercase tracking-wider text-muted-foreground"
                >
                  <Filter className="h-3 w-3" />
                  Quick Filters
                </motion.div>
              )}
            </AnimatePresence>

            <nav className="space-y-1">
              {filters.map((filter) => {
                const Icon = filter.icon;
                const isActive = selectedFilter === filter.id;

                return (
                  <motion.button
                    key={filter.id}
                    onClick={() => onFilterChange?.(filter.id)}
                    className={cn(
                      "flex w-full items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors",
                      isActive
                        ? "bg-sidebar-accent text-sidebar-accent-foreground"
                        : "text-sidebar-foreground/70 hover:bg-sidebar-accent/50 hover:text-sidebar-foreground",
                      collapsed && "justify-center px-2"
                    )}
                    whileHover={{ x: collapsed ? 0 : 2 }}
                    whileTap={{ scale: 0.98 }}
                  >
                    <Icon
                      className={cn(
                        "h-4 w-4 shrink-0",
                        filter.color,
                        isActive && !filter.color && "text-sidebar-primary"
                      )}
                    />
                    <AnimatePresence>
                      {!collapsed && (
                        <motion.span
                          initial={{ opacity: 0 }}
                          animate={{ opacity: 1 }}
                          exit={{ opacity: 0 }}
                          className="flex-1 text-left"
                        >
                          {filter.label}
                        </motion.span>
                      )}
                    </AnimatePresence>
                    <AnimatePresence>
                      {!collapsed && (
                        <motion.span
                          initial={{ opacity: 0 }}
                          animate={{ opacity: 1 }}
                          exit={{ opacity: 0 }}
                          className="rounded-full bg-sidebar-accent px-2 py-0.5 text-xs"
                        >
                          {filter.count}
                        </motion.span>
                      )}
                    </AnimatePresence>
                  </motion.button>
                );
              })}
            </nav>
          </div>

          <Separator className="my-4" />

          {/* Repositories */}
          <div>
            <AnimatePresence>
              {!collapsed && (
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  className="mb-2 flex items-center gap-2 px-2 text-xs font-medium uppercase tracking-wider text-muted-foreground"
                >
                  <Folder className="h-3 w-3" />
                  Repositories
                </motion.div>
              )}
            </AnimatePresence>

            <nav className="space-y-1">
              <motion.button
                onClick={() => onRepoSelect?.("all")}
                className={cn(
                  "flex w-full items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors",
                  selectedRepo === "all"
                    ? "bg-sidebar-accent text-sidebar-accent-foreground"
                    : "text-sidebar-foreground/70 hover:bg-sidebar-accent/50 hover:text-sidebar-foreground",
                  collapsed && "justify-center px-2"
                )}
                whileHover={{ x: collapsed ? 0 : 2 }}
                whileTap={{ scale: 0.98 }}
              >
                <GitBranch className="h-4 w-4 shrink-0" />
                <AnimatePresence>
                  {!collapsed && (
                    <motion.span
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      exit={{ opacity: 0 }}
                      className="flex-1 text-left"
                    >
                      All Repositories
                    </motion.span>
                  )}
                </AnimatePresence>
              </motion.button>

              {mockRepos.map((repo) => {
                const isActive = selectedRepo === repo.id;

                return (
                  <motion.button
                    key={repo.id}
                    onClick={() => onRepoSelect?.(repo.id)}
                    className={cn(
                      "flex w-full items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors",
                      isActive
                        ? "bg-sidebar-accent text-sidebar-accent-foreground"
                        : "text-sidebar-foreground/70 hover:bg-sidebar-accent/50 hover:text-sidebar-foreground",
                      collapsed && "justify-center px-2"
                    )}
                    whileHover={{ x: collapsed ? 0 : 2 }}
                    whileTap={{ scale: 0.98 }}
                  >
                    <div className="flex h-4 w-4 shrink-0 items-center justify-center rounded bg-primary/20 text-[10px] font-bold text-primary">
                      {repo.name.charAt(0).toUpperCase()}
                    </div>
                    <AnimatePresence>
                      {!collapsed && (
                        <>
                          <motion.span
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            exit={{ opacity: 0 }}
                            className="flex-1 truncate text-left"
                          >
                            {repo.name}
                          </motion.span>
                          <motion.span
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            exit={{ opacity: 0 }}
                            className="text-xs text-muted-foreground"
                          >
                            {repo.prCount}
                          </motion.span>
                        </>
                      )}
                    </AnimatePresence>
                  </motion.button>
                );
              })}
            </nav>
          </div>
        </div>
      </ScrollArea>
    </motion.aside>
  );
}
