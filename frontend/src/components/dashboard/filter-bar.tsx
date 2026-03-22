"use client";

import { useState } from "react";
import { Calendar, Search, X } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
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
import type { FilterOptions } from "@/lib/types";

interface FilterBarProps {
  filters: FilterOptions;
  onFiltersChange: (filters: FilterOptions) => void;
  repositories?: string[];
}

export function FilterBar({
  filters,
  onFiltersChange,
  repositories = [],
}: FilterBarProps) {
  const [dateRange, setDateRange] = useState<{ from?: Date; to?: Date }>({});

  const activeFilters =
    (filters.search?.trim() ? 1 : 0) +
    (filters.repository && filters.repository !== "all" ? 1 : 0) +
    (filters.dateRange ? 1 : 0);

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative min-w-[280px] flex-1">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={filters.search ?? ""}
            onChange={(event) =>
              onFiltersChange({
                ...filters,
                search: event.target.value,
              })
            }
            className="bg-secondary/30 pl-9"
            placeholder="Search by repo, PR URL, or PR number"
          />
        </div>

        {repositories.length > 0 ? (
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" className="bg-secondary/30">
                Repository
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="start" className="w-56">
              <DropdownMenuLabel>Filter by repository</DropdownMenuLabel>
              <DropdownMenuSeparator />
              <DropdownMenuItem
                onClick={() =>
                  onFiltersChange({
                    ...filters,
                    repository: "all",
                  })
                }
              >
                All repositories
              </DropdownMenuItem>
              {repositories.map((repository) => (
                <DropdownMenuItem
                  key={repository}
                  onClick={() =>
                    onFiltersChange({
                      ...filters,
                      repository,
                    })
                  }
                >
                  {repository}
                </DropdownMenuItem>
              ))}
            </DropdownMenuContent>
          </DropdownMenu>
        ) : null}

        <Popover>
          <PopoverTrigger asChild>
            <Button variant="outline" className="gap-2 bg-secondary/30">
              <Calendar className="h-4 w-4" />
              Date Range
            </Button>
          </PopoverTrigger>
          <PopoverContent align="start" className="w-auto p-0">
            <CalendarComponent
              mode="range"
              selected={{
                from: dateRange.from,
                to: dateRange.to,
              }}
              onSelect={(range) => {
                const nextRange = {
                  from: range?.from,
                  to: range?.to,
                };

                setDateRange(nextRange);

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

        {activeFilters > 0 ? (
          <Button
            variant="ghost"
            onClick={() => {
              setDateRange({});
              onFiltersChange({
                repository: "all",
                quickFilter: filters.quickFilter ?? "all",
                search: "",
              });
            }}
            className="gap-2 text-muted-foreground"
          >
            <X className="h-4 w-4" />
            Clear
          </Button>
        ) : null}
      </div>

      {activeFilters > 0 ? (
        <div className="flex flex-wrap items-center gap-2">
          {filters.search?.trim() ? (
            <Badge variant="secondary">Search: {filters.search}</Badge>
          ) : null}
          {filters.repository && filters.repository !== "all" ? (
            <Badge variant="secondary">Repo: {filters.repository}</Badge>
          ) : null}
          {filters.dateRange ? <Badge variant="secondary">Date range</Badge> : null}
        </div>
      ) : null}
    </div>
  );
}
