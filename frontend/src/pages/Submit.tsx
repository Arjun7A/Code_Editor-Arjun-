import React from "react";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Header } from "@/components/layout/header";
import { Sidebar } from "@/components/layout/sidebar";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { useToast } from "@/hooks/use-toast";
import {
  GitPullRequest,
  Link,
  Upload,
  Shield,
  Brain,
  FileCode,
  AlertTriangle,
  CheckCircle2,
  Loader2,
  Github,
  GitBranch,
  Code2,
  Sparkles,
  Zap,
  Lock,
  ScanLine,
} from "lucide-react";
import { cn } from "@/lib/utils";

type AnalysisStep = {
  id: string;
  label: string;
  status: "pending" | "running" | "complete" | "error";
  icon: React.ReactNode;
};

export default function SubmitPRPage() {
  const navigate = useNavigate();
  const { toast } = useToast();
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [submissionMethod, setSubmissionMethod] = useState<"url" | "manual">(
    "url"
  );
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisProgress, setAnalysisProgress] = useState(0);
  const [currentStep, setCurrentStep] = useState(0);

  const [formData, setFormData] = useState({
    prUrl: "",
    repository: "",
    branch: "",
    title: "",
    description: "",
    diffContent: "",
    enableAI: true,
    enableML: true,
    enableSecurityScan: true,
    priority: "normal",
    notifyOnComplete: true,
  });

  const analysisSteps: AnalysisStep[] = [
    {
      id: "fetch",
      label: "Fetching PR Data",
      status:
        currentStep > 0 ? "complete" : currentStep === 0 ? "running" : "pending",
      icon: <GitPullRequest className="h-4 w-4" />,
    },
    {
      id: "scan",
      label: "Security Scanning",
      status:
        currentStep > 1 ? "complete" : currentStep === 1 ? "running" : "pending",
      icon: <ScanLine className="h-4 w-4" />,
    },
    {
      id: "ai",
      label: "AI Analysis",
      status:
        currentStep > 2 ? "complete" : currentStep === 2 ? "running" : "pending",
      icon: <Brain className="h-4 w-4" />,
    },
    {
      id: "ml",
      label: "ML Risk Assessment",
      status:
        currentStep > 3 ? "complete" : currentStep === 3 ? "running" : "pending",
      icon: <Sparkles className="h-4 w-4" />,
    },
    {
      id: "blockchain",
      label: "Blockchain Verification",
      status:
        currentStep > 4 ? "complete" : currentStep === 4 ? "running" : "pending",
      icon: <Lock className="h-4 w-4" />,
    },
  ];

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (submissionMethod === "url" && !formData.prUrl) {
      toast({
        title: "Error",
        description: "Please enter a valid PR URL",
        variant: "destructive",
      });
      return;
    }

    if (submissionMethod === "manual" && !formData.diffContent) {
      toast({
        title: "Error",
        description: "Please enter the code diff content",
        variant: "destructive",
      });
      return;
    }

    setIsAnalyzing(true);
    setAnalysisProgress(0);
    setCurrentStep(0);

    // Simulate analysis steps
    for (let i = 0; i < 5; i++) {
      setCurrentStep(i);
      const stepDuration = 800 + Math.random() * 400;

      for (let p = 0; p <= 100; p += 5) {
        await new Promise((r) => setTimeout(r, stepDuration / 20));
        setAnalysisProgress(((i * 100 + p) / 5));
      }
    }

    setCurrentStep(5);
    setAnalysisProgress(100);

    await new Promise((r) => setTimeout(r, 500));

    toast({
      title: "Analysis Complete",
      description: "Your PR has been analyzed successfully",
    });

    // Navigate to a sample PR detail page
    navigate("/pr/1");
  };

  return (
    <div className="flex h-screen bg-background">
      <Sidebar />

      <div className="flex flex-1 flex-col overflow-hidden">
        <Header />

        <main className="flex-1 overflow-y-auto p-6">
          <div className="mx-auto max-w-4xl">
            {/* Header */}
            <div className="mb-8">
              <h1 className="text-3xl font-bold text-foreground">
                Submit PR for Analysis
              </h1>
              <p className="mt-2 text-muted-foreground">
                Submit a pull request for comprehensive security analysis,
                AI-powered code review, and ML risk assessment.
              </p>
            </div>

            {isAnalyzing ? (
              <Card className="border-border/50 bg-card/50 backdrop-blur-sm">
                <CardHeader className="text-center">
                  <div className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-primary/10">
                    <Shield className="h-8 w-8 animate-pulse text-primary" />
                  </div>
                  <CardTitle className="text-2xl">Analyzing PR</CardTitle>
                  <CardDescription>
                    Please wait while we perform comprehensive security analysis
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-8">
                  <div className="space-y-2">
                    <div className="flex items-center justify-between text-sm">
                      <span className="text-muted-foreground">
                        Overall Progress
                      </span>
                      <span className="font-mono text-foreground">
                        {Math.round(analysisProgress)}%
                      </span>
                    </div>
                    <Progress value={analysisProgress} className="h-2" />
                  </div>

                  <div className="space-y-4">
                    {analysisSteps.map((step, index) => (
                      <div
                        key={step.id}
                        className={cn(
                          "flex items-center gap-4 rounded-lg border p-4 transition-all duration-300",
                          step.status === "complete" &&
                            "border-success/30 bg-success/5",
                          step.status === "running" &&
                            "border-primary/50 bg-primary/5",
                          step.status === "pending" &&
                            "border-border/30 bg-muted/20 opacity-50"
                        )}
                      >
                        <div
                          className={cn(
                            "flex h-10 w-10 items-center justify-center rounded-full",
                            step.status === "complete" &&
                              "bg-success/20 text-success",
                            step.status === "running" &&
                              "bg-primary/20 text-primary",
                            step.status === "pending" &&
                              "bg-muted text-muted-foreground"
                          )}
                        >
                          {step.status === "running" ? (
                            <Loader2 className="h-5 w-5 animate-spin" />
                          ) : step.status === "complete" ? (
                            <CheckCircle2 className="h-5 w-5" />
                          ) : (
                            step.icon
                          )}
                        </div>
                        <div className="flex-1">
                          <p
                            className={cn(
                              "font-medium",
                              step.status === "complete" && "text-success",
                              step.status === "running" && "text-primary",
                              step.status === "pending" && "text-muted-foreground"
                            )}
                          >
                            {step.label}
                          </p>
                          <p className="text-sm text-muted-foreground">
                            {step.status === "running"
                              ? "In progress..."
                              : step.status === "complete"
                                ? "Completed"
                                : "Waiting..."}
                          </p>
                        </div>
                        <Badge
                          variant={
                            step.status === "complete"
                              ? "default"
                              : step.status === "running"
                                ? "secondary"
                                : "outline"
                          }
                          className={cn(
                            step.status === "complete" &&
                              "bg-success/20 text-success border-success/30"
                          )}
                        >
                          {step.status === "running"
                            ? "Running"
                            : step.status === "complete"
                              ? "Done"
                              : `Step ${index + 1}`}
                        </Badge>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            ) : (
              <form onSubmit={handleSubmit} className="space-y-6">
                {/* Submission Method Toggle */}
                <Card className="border-border/50 bg-card/50 backdrop-blur-sm">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Link className="h-5 w-5 text-primary" />
                      Submission Method
                    </CardTitle>
                    <CardDescription>
                      Choose how you want to submit your pull request
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="grid grid-cols-2 gap-4">
                      <button
                        type="button"
                        onClick={() => setSubmissionMethod("url")}
                        className={cn(
                          "flex flex-col items-center gap-3 rounded-lg border-2 p-6 transition-all",
                          submissionMethod === "url"
                            ? "border-primary bg-primary/5"
                            : "border-border/50 hover:border-border hover:bg-muted/30"
                        )}
                      >
                        <div
                          className={cn(
                            "flex h-12 w-12 items-center justify-center rounded-full",
                            submissionMethod === "url"
                              ? "bg-primary/20 text-primary"
                              : "bg-muted text-muted-foreground"
                          )}
                        >
                          <Github className="h-6 w-6" />
                        </div>
                        <div className="text-center">
                          <p className="font-semibold text-foreground">
                            PR URL
                          </p>
                          <p className="text-sm text-muted-foreground">
                            Paste GitHub/GitLab PR link
                          </p>
                        </div>
                      </button>

                      <button
                        type="button"
                        onClick={() => setSubmissionMethod("manual")}
                        className={cn(
                          "flex flex-col items-center gap-3 rounded-lg border-2 p-6 transition-all",
                          submissionMethod === "manual"
                            ? "border-primary bg-primary/5"
                            : "border-border/50 hover:border-border hover:bg-muted/30"
                        )}
                      >
                        <div
                          className={cn(
                            "flex h-12 w-12 items-center justify-center rounded-full",
                            submissionMethod === "manual"
                              ? "bg-primary/20 text-primary"
                              : "bg-muted text-muted-foreground"
                          )}
                        >
                          <Code2 className="h-6 w-6" />
                        </div>
                        <div className="text-center">
                          <p className="font-semibold text-foreground">
                            Manual Entry
                          </p>
                          <p className="text-sm text-muted-foreground">
                            Paste diff content directly
                          </p>
                        </div>
                      </button>
                    </div>
                  </CardContent>
                </Card>

                {/* PR Details */}
                <Card className="border-border/50 bg-card/50 backdrop-blur-sm">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <GitPullRequest className="h-5 w-5 text-primary" />
                      PR Details
                    </CardTitle>
                    <CardDescription>
                      {submissionMethod === "url"
                        ? "Enter the pull request URL to analyze"
                        : "Enter the pull request details manually"}
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    {submissionMethod === "url" ? (
                      <div className="space-y-2">
                        <Label htmlFor="prUrl">Pull Request URL</Label>
                        <div className="relative">
                          <Github className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                          <Input
                            id="prUrl"
                            placeholder="https://github.com/org/repo/pull/123"
                            value={formData.prUrl}
                            onChange={(e) =>
                              setFormData({ ...formData, prUrl: e.target.value })
                            }
                            className="pl-10"
                          />
                        </div>
                        <p className="text-xs text-muted-foreground">
                          Supports GitHub, GitLab, and Bitbucket URLs
                        </p>
                      </div>
                    ) : (
                      <>
                        <div className="grid grid-cols-2 gap-4">
                          <div className="space-y-2">
                            <Label htmlFor="repository">Repository</Label>
                            <div className="relative">
                              <FileCode className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                              <Input
                                id="repository"
                                placeholder="org/repository"
                                value={formData.repository}
                                onChange={(e) =>
                                  setFormData({
                                    ...formData,
                                    repository: e.target.value,
                                  })
                                }
                                className="pl-10"
                              />
                            </div>
                          </div>
                          <div className="space-y-2">
                            <Label htmlFor="branch">Branch</Label>
                            <div className="relative">
                              <GitBranch className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                              <Input
                                id="branch"
                                placeholder="feature/new-feature"
                                value={formData.branch}
                                onChange={(e) =>
                                  setFormData({
                                    ...formData,
                                    branch: e.target.value,
                                  })
                                }
                                className="pl-10"
                              />
                            </div>
                          </div>
                        </div>

                        <div className="space-y-2">
                          <Label htmlFor="title">PR Title</Label>
                          <Input
                            id="title"
                            placeholder="Add new authentication feature"
                            value={formData.title}
                            onChange={(e) =>
                              setFormData({ ...formData, title: e.target.value })
                            }
                          />
                        </div>

                        <div className="space-y-2">
                          <Label htmlFor="description">Description</Label>
                          <Textarea
                            id="description"
                            placeholder="Describe the changes in this PR..."
                            value={formData.description}
                            onChange={(e) =>
                              setFormData({
                                ...formData,
                                description: e.target.value,
                              })
                            }
                            rows={3}
                          />
                        </div>

                        <div className="space-y-2">
                          <Label htmlFor="diffContent">Code Diff</Label>
                          <Textarea
                            id="diffContent"
                            placeholder="Paste your git diff content here..."
                            value={formData.diffContent}
                            onChange={(e) =>
                              setFormData({
                                ...formData,
                                diffContent: e.target.value,
                              })
                            }
                            rows={10}
                            className="font-mono text-sm"
                          />
                        </div>
                      </>
                    )}
                  </CardContent>
                </Card>

                {/* Analysis Options */}
                <Card className="border-border/50 bg-card/50 backdrop-blur-sm">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Zap className="h-5 w-5 text-primary" />
                      Analysis Options
                    </CardTitle>
                    <CardDescription>
                      Configure which analysis features to enable
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-6">
                    <div className="grid gap-4 md:grid-cols-3">
                      <div
                        className={cn(
                          "flex items-center justify-between rounded-lg border p-4 transition-colors",
                          formData.enableAI
                            ? "border-primary/30 bg-primary/5"
                            : "border-border/50"
                        )}
                      >
                        <div className="flex items-center gap-3">
                          <div
                            className={cn(
                              "flex h-9 w-9 items-center justify-center rounded-lg",
                              formData.enableAI
                                ? "bg-primary/20 text-primary"
                                : "bg-muted text-muted-foreground"
                            )}
                          >
                            <Brain className="h-4 w-4" />
                          </div>
                          <div>
                            <p className="font-medium text-foreground">
                              AI Analysis
                            </p>
                            <p className="text-xs text-muted-foreground">
                              GPT-4 powered
                            </p>
                          </div>
                        </div>
                        <Switch
                          checked={formData.enableAI}
                          onCheckedChange={(checked: boolean) =>
                            setFormData({ ...formData, enableAI: checked })
                          }
                        />
                      </div>

                      <div
                        className={cn(
                          "flex items-center justify-between rounded-lg border p-4 transition-colors",
                          formData.enableML
                            ? "border-accent/30 bg-accent/5"
                            : "border-border/50"
                        )}
                      >
                        <div className="flex items-center gap-3">
                          <div
                            className={cn(
                              "flex h-9 w-9 items-center justify-center rounded-lg",
                              formData.enableML
                                ? "bg-accent/20 text-accent"
                                : "bg-muted text-muted-foreground"
                            )}
                          >
                            <Sparkles className="h-4 w-4" />
                          </div>
                          <div>
                            <p className="font-medium text-foreground">
                              ML Scoring
                            </p>
                            <p className="text-xs text-muted-foreground">
                              Risk prediction
                            </p>
                          </div>
                        </div>
                        <Switch
                          checked={formData.enableML}
                          onCheckedChange={(checked: boolean) =>
                            setFormData({ ...formData, enableML: checked })
                          }
                        />
                      </div>

                      <div
                        className={cn(
                          "flex items-center justify-between rounded-lg border p-4 transition-colors",
                          formData.enableSecurityScan
                            ? "border-success/30 bg-success/5"
                            : "border-border/50"
                        )}
                      >
                        <div className="flex items-center gap-3">
                          <div
                            className={cn(
                              "flex h-9 w-9 items-center justify-center rounded-lg",
                              formData.enableSecurityScan
                                ? "bg-success/20 text-success"
                                : "bg-muted text-muted-foreground"
                            )}
                          >
                            <Shield className="h-4 w-4" />
                          </div>
                          <div>
                            <p className="font-medium text-foreground">
                              Security Scan
                            </p>
                            <p className="text-xs text-muted-foreground">
                              SAST/Secrets
                            </p>
                          </div>
                        </div>
                        <Switch
                          checked={formData.enableSecurityScan}
                          onCheckedChange={(checked: boolean) =>
                            setFormData({
                              ...formData,
                              enableSecurityScan: checked,
                            })
                          }
                        />
                      </div>
                    </div>

                    <div className="grid gap-4 md:grid-cols-2">
                      <div className="space-y-2">
                        <Label htmlFor="priority">Analysis Priority</Label>
                        <Select
                          value={formData.priority}
                          onValueChange={(value: string) =>
                            setFormData({ ...formData, priority: value })
                          }
                        >
                          <SelectTrigger id="priority">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="low">
                              <span className="flex items-center gap-2">
                                <span className="h-2 w-2 rounded-full bg-muted-foreground" />
                                Low Priority
                              </span>
                            </SelectItem>
                            <SelectItem value="normal">
                              <span className="flex items-center gap-2">
                                <span className="h-2 w-2 rounded-full bg-primary" />
                                Normal Priority
                              </span>
                            </SelectItem>
                            <SelectItem value="high">
                              <span className="flex items-center gap-2">
                                <span className="h-2 w-2 rounded-full bg-warning" />
                                High Priority
                              </span>
                            </SelectItem>
                            <SelectItem value="critical">
                              <span className="flex items-center gap-2">
                                <span className="h-2 w-2 rounded-full bg-critical" />
                                Critical Priority
                              </span>
                            </SelectItem>
                          </SelectContent>
                        </Select>
                      </div>

                      <div className="flex items-end">
                        <div className="flex w-full items-center justify-between rounded-lg border border-border/50 p-4">
                          <div className="flex items-center gap-3">
                            <AlertTriangle className="h-4 w-4 text-muted-foreground" />
                            <span className="text-sm text-foreground">
                              Notify on completion
                            </span>
                          </div>
                          <Switch
                            checked={formData.notifyOnComplete}
                            onCheckedChange={(checked: boolean) =>
                              setFormData({
                                ...formData,
                                notifyOnComplete: checked,
                              })
                            }
                          />
                        </div>
                      </div>
                    </div>
                  </CardContent>
                </Card>

                {/* Submit Button */}
                <div className="flex items-center justify-between">
                  <p className="text-sm text-muted-foreground">
                    Analysis typically takes 30-60 seconds
                  </p>
                  <Button
                    type="submit"
                    size="lg"
                    className="gap-2 bg-primary hover:bg-primary/90"
                  >
                    <Upload className="h-4 w-4" />
                    Start Analysis
                  </Button>
                </div>
              </form>
            )}
          </div>
        </main>
      </div>
    </div>
  );
}
