"use client";

import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { ChevronDown, ChevronRight, FileCode, Plus, Minus } from "lucide-react";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import type { CodeDiff, DiffLine } from "@/lib/types";

interface CodeDiffViewerProps {
  diffs: CodeDiff[];
  className?: string;
}

const statusColors = {
  added: "bg-success/20 text-success",
  modified: "bg-warning/20 text-warning",
  deleted: "bg-destructive/20 text-destructive",
  renamed: "bg-info/20 text-info",
};

export function CodeDiffViewer({ diffs, className }: CodeDiffViewerProps) {
  const [expandedFiles, setExpandedFiles] = useState<Set<string>>(
    new Set(diffs.slice(0, 2).map((d) => d.filename))
  );

  const toggleFile = (filename: string) => {
    const newExpanded = new Set(expandedFiles);
    if (newExpanded.has(filename)) {
      newExpanded.delete(filename);
    } else {
      newExpanded.add(filename);
    }
    setExpandedFiles(newExpanded);
  };

  return (
    <div className={cn("space-y-3", className)}>
      {diffs.map((diff, index) => (
        <motion.div
          key={diff.filename}
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: index * 0.05 }}
          className="overflow-hidden rounded-xl border border-border bg-card"
        >
          {/* File Header */}
          <button
            type="button"
            onClick={() => toggleFile(diff.filename)}
            className="flex w-full items-center gap-3 border-b border-border bg-muted/30 px-4 py-3 transition-colors hover:bg-muted/50"
          >
            {expandedFiles.has(diff.filename) ? (
              <ChevronDown className="h-4 w-4 text-muted-foreground" />
            ) : (
              <ChevronRight className="h-4 w-4 text-muted-foreground" />
            )}
            <FileCode className="h-4 w-4 text-primary" />
            <span className="flex-1 text-left font-mono text-sm text-foreground">
              {diff.filename}
            </span>
            <Badge variant="outline" className={statusColors[diff.status]}>
              {diff.status}
            </Badge>
            <div className="flex items-center gap-2 text-xs">
              <span className="flex items-center gap-1 text-success">
                <Plus className="h-3 w-3" />
                {diff.additions}
              </span>
              <span className="flex items-center gap-1 text-destructive">
                <Minus className="h-3 w-3" />
                {diff.deletions}
              </span>
            </div>
          </button>

          {/* Code Content */}
          <AnimatePresence>
            {expandedFiles.has(diff.filename) && (
              <motion.div
                initial={{ height: 0, opacity: 0 }}
                animate={{ height: "auto", opacity: 1 }}
                exit={{ height: 0, opacity: 0 }}
                transition={{ duration: 0.2 }}
              >
                <ScrollArea className="max-h-96">
                  <div className="font-mono text-sm">
                    {diff.hunks.map((hunk, hunkIndex) => (
                      <div key={hunkIndex}>
                        {/* Hunk Header */}
                        <div className="bg-info/10 px-4 py-1 text-xs text-info">
                          @@ -{hunk.oldStart},{hunk.oldLines} +{hunk.newStart},
                          {hunk.newLines} @@
                        </div>
                        {/* Lines */}
                        {hunk.lines.map((line, lineIndex) => (
                          <DiffLineComponent
                            key={`${hunkIndex}-${lineIndex}`}
                            line={line}
                          />
                        ))}
                      </div>
                    ))}
                  </div>
                </ScrollArea>
              </motion.div>
            )}
          </AnimatePresence>
        </motion.div>
      ))}
    </div>
  );
}

function DiffLineComponent({ line }: { line: DiffLine }) {
  const bgColor =
    line.type === "addition"
      ? "bg-success/10 border-l-2 border-success"
      : line.type === "deletion"
        ? "bg-destructive/10 border-l-2 border-destructive"
        : "bg-transparent border-l-2 border-transparent";

  const textColor =
    line.type === "addition"
      ? "text-success"
      : line.type === "deletion"
        ? "text-destructive"
        : "text-muted-foreground";

  const prefix =
    line.type === "addition" ? "+" : line.type === "deletion" ? "-" : " ";

  return (
    <div className={cn("flex", bgColor)}>
      {/* Line Numbers */}
      <div className="flex shrink-0 select-none border-r border-border bg-muted/20 text-xs text-muted-foreground">
        <span className="w-12 px-2 py-0.5 text-right">
          {line.oldLineNumber || ""}
        </span>
        <span className="w-12 px-2 py-0.5 text-right">
          {line.newLineNumber || ""}
        </span>
      </div>
      {/* Content */}
      <div className="flex-1 overflow-x-auto">
        <pre className={cn("px-4 py-0.5", textColor)}>
          <span className="select-none">{prefix}</span>
          {line.content}
        </pre>
      </div>
    </div>
  );
}
