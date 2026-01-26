"use client";

import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Search, Filter, X, Calendar, ChevronDown } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import { Calendar as CalendarComponent } from "@/components/ui/calendar";
import { Badge } from "@/components/ui/badge";
import type { FilterOptions, Verdict, RiskLevel } from "@/lib/types";
import { cn } from "@/lib/utils";

interface FilterBarProps {
  filters: FilterOptions;
  onFiltersChange: (filters: FilterOptions) => void;
  repositories?: string[];
}

const verdictOptions: { value: Verdict | "all"; label: string }[] = [
  { value: "all", label: "All Verdicts" },
  { value: "approved", label: "Approved" },
  { value: "blocked", label: "Blocked" },
  { value: "manual_review", label: "Manual Review" },
];

const riskLevelOptions: { value: RiskLevel | "all"; label: string }[] = [
  { value: "all", label: "All Risk Levels" },
  { value: "critical", label: "Critical" },
  { value: "high", label: "High" },
  { value: "medium", label: "Medium" },
  { value: "low", label: "Low" },
];

export function FilterBar({
  filters,
  onFiltersChange,
  repositories = [],
}: FilterBarProps) {
  const [searchFocused, setSearchFocused] = useState(false);
  const [dateRange, setDateRange] = useState<{
    from?: Date;
    to?: Date;
  }>({});

  const activeFiltersCount =
    (filters.verdict && filters.verdict !== "all" ? 1 : 0) +
    (filters.riskLevel && filters.riskLevel !== "all" ? 1 : 0) +
    (filters.repository && filters.repository !== "all" ? 1 : 0) +
    (filters.dateRange ? 1 : 0);

  const clearFilters = () => {
    onFiltersChange({
      verdict: "all",
      riskLevel: "all",
      repository: "all",
      search: "",
      dateRange: undefined,
    });
    setDateRange({});
  };

  const removeFilter = (key: keyof FilterOptions) => {
    if (key === "dateRange") {
      setDateRange({});
    }
    onFiltersChange({
      ...filters,
      [key]: key === "search" ? "" : "all",
    });
  };

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-3">
        {/* Search */}
        <motion.div
          className="relative flex-1 min-w-50"
          animate={{ scale: searchFocused ? 1.01 : 1 }}
          transition={{ duration: 0.2 }}
        >
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Search PRs, repositories, authors..."
            value={filters.search || ""}
            onChange={(e) =>
              onFiltersChange({ ...filters, search: e.target.value })
            }
            onFocus={() => setSearchFocused(true)}
            onBlur={() => setSearchFocused(false)}
            className="h-10 bg-secondary/30 pl-9"
          />
        </motion.div>

        {/* Verdict Filter */}
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button
              variant="outline"
              className="h-10 gap-2 bg-secondary/30"
            >
              <Filter className="h-4 w-4" />
              Verdict
              <ChevronDown className="h-4 w-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="start" className="w-48">
            <DropdownMenuLabel>Filter by Verdict</DropdownMenuLabel>
            <DropdownMenuSeparator />
            {verdictOptions.map((option) => (
              <DropdownMenuItem
                key={option.value}
                onClick={() =>
                  onFiltersChange({ ...filters, verdict: option.value })
                }
                className={cn(
                  filters.verdict === option.value && "bg-accent"
                )}
              >
                {option.label}
              </DropdownMenuItem>
            ))}
          </DropdownMenuContent>
        </DropdownMenu>

        {/* Risk Level Filter */}
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button
              variant="outline"
              className="h-10 gap-2 bg-secondary/30"
            >
              Risk Level
              <ChevronDown className="h-4 w-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="start" className="w-48">
            <DropdownMenuLabel>Filter by Risk</DropdownMenuLabel>
            <DropdownMenuSeparator />
            {riskLevelOptions.map((option) => (
              <DropdownMenuItem
                key={option.value}
                onClick={() =>
                  onFiltersChange({ ...filters, riskLevel: option.value })
                }
                className={cn(
                  filters.riskLevel === option.value && "bg-accent"
                )}
              >
                {option.label}
              </DropdownMenuItem>
            ))}
          </DropdownMenuContent>
        </DropdownMenu>

        {/* Date Range */}
        <Popover>
          <PopoverTrigger asChild>
            <Button
              variant="outline"
              className="h-10 gap-2 bg-secondary/30"
            >
              <Calendar className="h-4 w-4" />
              Date Range
              <ChevronDown className="h-4 w-4" />
            </Button>
          </PopoverTrigger>
          <PopoverContent className="w-auto p-0" align="start">
            <CalendarComponent
              mode="range"
              selected={{
                from: dateRange.from,
                to: dateRange.to,
              }}
              onSelect={(range) => {
                setDateRange({
                  from: range?.from,
                  to: range?.to,
                });
                if (range?.from && range?.to) {
                  onFiltersChange({
                    ...filters,
                    dateRange: {
                      start: range.from.toISOString(),
                      end: range.to.toISOString(),
                    },
                  });
                }
              }}
              numberOfMonths={2}
            />
          </PopoverContent>
        </Popover>

        {/* Repository Filter */}
        {repositories.length > 0 && (
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                variant="outline"
                className="h-10 gap-2 bg-secondary/30"
              >
                Repository
                <ChevronDown className="h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="start" className="w-48">
              <DropdownMenuLabel>Filter by Repository</DropdownMenuLabel>
              <DropdownMenuSeparator />
              <DropdownMenuItem
                onClick={() =>
                  onFiltersChange({ ...filters, repository: "all" })
                }
                className={cn(filters.repository === "all" && "bg-accent")}
              >
                All Repositories
              </DropdownMenuItem>
              {repositories.map((repo) => (
                <DropdownMenuItem
                  key={repo}
                  onClick={() =>
                    onFiltersChange({ ...filters, repository: repo })
                  }
                  className={cn(filters.repository === repo && "bg-accent")}
                >
                  {repo}
                </DropdownMenuItem>
              ))}
            </DropdownMenuContent>
          </DropdownMenu>
        )}

        {/* Clear Filters */}
        {activeFiltersCount > 0 && (
          <Button
            variant="ghost"
            size="sm"
            onClick={clearFilters}
            className="h-10 gap-1 text-muted-foreground hover:text-foreground"
          >
            <X className="h-4 w-4" />
            Clear all
          </Button>
        )}
      </div>

      {/* Active Filters */}
      <AnimatePresence>
        {activeFiltersCount > 0 && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: "auto" }}
            exit={{ opacity: 0, height: 0 }}
            className="flex flex-wrap items-center gap-2"
          >
            <span className="text-sm text-muted-foreground">
              Active filters:
            </span>
            {filters.verdict && filters.verdict !== "all" && (
              <FilterChip
                label={`Verdict: ${filters.verdict.replace("_", " ")}`}
                onRemove={() => removeFilter("verdict")}
              />
            )}
            {filters.riskLevel && filters.riskLevel !== "all" && (
              <FilterChip
                label={`Risk: ${filters.riskLevel}`}
                onRemove={() => removeFilter("riskLevel")}
              />
            )}
            {filters.repository && filters.repository !== "all" && (
              <FilterChip
                label={`Repo: ${filters.repository}`}
                onRemove={() => removeFilter("repository")}
              />
            )}
            {filters.dateRange && (
              <FilterChip
                label="Date range"
                onRemove={() => removeFilter("dateRange")}
              />
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

function FilterChip({
  label,
  onRemove,
}: {
  label: string;
  onRemove: () => void;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.8 }}
      animate={{ opacity: 1, scale: 1 }}
      exit={{ opacity: 0, scale: 0.8 }}
    >
      <Badge
        variant="secondary"
        className="gap-1 bg-primary/10 text-primary hover:bg-primary/20"
      >
        {label}
        <button
          type="button"
          onClick={onRemove}
          className="ml-1 rounded-full hover:bg-primary/20"
        >
          <X className="h-3 w-3" />
        </button>
      </Badge>
    </motion.div>
  );
}
