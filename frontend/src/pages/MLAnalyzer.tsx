import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Header } from "@/components/layout/header";
import { Sidebar } from "@/components/layout/sidebar";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Badge } from "@/components/ui/badge";
import {
    Card,
    CardContent,
    CardDescription,
    CardHeader,
    CardTitle,
} from "@/components/ui/card";
import {
    Tooltip,
    TooltipContent,
    TooltipProvider,
    TooltipTrigger,
} from "@/components/ui/tooltip";
import { Slider } from "@/components/ui/slider";
import { useToast } from "@/hooks/use-toast";
import {
    Brain,
    Sparkles,
    Shield,
    AlertTriangle,
    CheckCircle2,
    Loader2,
    BarChart3,
    TrendingUp,
    TrendingDown,
    Info,
    Cpu,
    FileCode,
    GitCommit,
    User,
    Clock,
    Bug,
    TestTube2,
    Code2,
    History,
    Zap,
    RotateCcw,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { predictRisk } from "@/api/client";

// Feature definitions for the form
const FEATURES = [
    {
        key: "files_changed",
        label: "Files Changed",
        icon: FileCode,
        type: "number",
        min: 0,
        max: 200,
        defaultValue: 5,
        description: "Number of files modified in the PR",
    },
    {
        key: "lines_added",
        label: "Lines Added",
        icon: TrendingUp,
        type: "number",
        min: 0,
        max: 10000,
        defaultValue: 100,
        description: "Total lines of code added",
    },
    {
        key: "lines_deleted",
        label: "Lines Deleted",
        icon: TrendingDown,
        type: "number",
        min: 0,
        max: 5000,
        defaultValue: 30,
        description: "Total lines of code removed",
    },
    {
        key: "commit_count",
        label: "Commit Count",
        icon: GitCommit,
        type: "number",
        min: 1,
        max: 100,
        defaultValue: 3,
        description: "Number of commits in the PR",
    },
    {
        key: "author_reputation",
        label: "Author Reputation",
        icon: User,
        type: "slider",
        min: 0,
        max: 1,
        step: 0.01,
        defaultValue: 0.7,
        description: "Developer's historical track record (0 = new, 1 = trusted)",
    },
    {
        key: "time_of_day",
        label: "Hour of Submission",
        icon: Clock,
        type: "number",
        min: 0,
        max: 23,
        defaultValue: 14,
        description: "Hour (0-23) when the PR was submitted",
    },
    {
        key: "day_of_week",
        label: "Day of Week",
        icon: Clock,
        type: "number",
        min: 0,
        max: 6,
        defaultValue: 2,
        description: "Day (0=Mon, 6=Sun) when submitted",
    },
    {
        key: "has_test_changes",
        label: "Has Test Changes",
        icon: TestTube2,
        type: "toggle",
        defaultValue: true,
        description: "Whether test files were modified",
    },
    {
        key: "num_issues",
        label: "Issues / Comments",
        icon: Bug,
        type: "number",
        min: 0,
        max: 50,
        defaultValue: 2,
        description: "Number of review comments or linked issues",
    },
    {
        key: "num_severity",
        label: "Security Severity",
        icon: Shield,
        type: "number",
        min: 0,
        max: 20,
        defaultValue: 0,
        description: "Number of security-sensitive files touched",
    },
    {
        key: "lang_ratio",
        label: "Language Ratio",
        icon: Code2,
        type: "slider",
        min: 0,
        max: 1,
        step: 0.01,
        defaultValue: 0.5,
        description: "JS/TS ratio vs Python (0=Python, 1=JS/TS)",
    },
    {
        key: "historical_vuln_rate",
        label: "Historical Vuln Rate",
        icon: History,
        type: "slider",
        min: 0,
        max: 1,
        step: 0.01,
        defaultValue: 0.05,
        description: "Author's past vulnerability introduction rate",
    },
];

type PredictionResult = {
    risk_score: number;
    risk_label: string;
    risk_percentage: number;
    feature_importance: Record<string, number>;
    model_version: string;
    using_fallback: boolean;
};

export default function MLAnalyzerPage() {
    const { toast } = useToast();
    const [isAnalyzing, setIsAnalyzing] = useState(false);
    const [prediction, setPrediction] = useState<PredictionResult | null>(null);
    const [error, setError] = useState<string | null>(null);

    // Build initial feature state
    const initialFeatures: Record<string, number | boolean> = {};
    FEATURES.forEach((f) => {
        initialFeatures[f.key] = f.defaultValue;
    });
    const [features, setFeatures] =
        useState<Record<string, number | boolean>>(initialFeatures);

    const updateFeature = (key: string, value: number | boolean) => {
        setFeatures((prev) => ({ ...prev, [key]: value }));
    };

    const resetFeatures = () => {
        const reset: Record<string, number | boolean> = {};
        FEATURES.forEach((f) => {
            reset[f.key] = f.defaultValue;
        });
        setFeatures(reset);
        setPrediction(null);
        setError(null);
    };

    // Preset scenarios
    const loadPreset = (preset: "safe" | "risky" | "borderline") => {
        const presets = {
            safe: {
                files_changed: 2,
                lines_added: 30,
                lines_deleted: 10,
                commit_count: 1,
                author_reputation: 0.95,
                time_of_day: 10,
                day_of_week: 2,
                has_test_changes: true,
                num_issues: 0,
                num_severity: 0,
                lang_ratio: 0.5,
                historical_vuln_rate: 0.0,
            },
            risky: {
                files_changed: 50,
                lines_added: 3000,
                lines_deleted: 500,
                commit_count: 15,
                author_reputation: 0.1,
                time_of_day: 3,
                day_of_week: 6,
                has_test_changes: false,
                num_issues: 8,
                num_severity: 6,
                lang_ratio: 0.3,
                historical_vuln_rate: 0.5,
            },
            borderline: {
                files_changed: 12,
                lines_added: 250,
                lines_deleted: 80,
                commit_count: 5,
                author_reputation: 0.5,
                time_of_day: 16,
                day_of_week: 4,
                has_test_changes: false,
                num_issues: 3,
                num_severity: 2,
                lang_ratio: 0.6,
                historical_vuln_rate: 0.15,
            },
        };
        setFeatures(presets[preset] as Record<string, number | boolean>);
        setPrediction(null);
    };

    const handlePredict = async () => {
        setIsAnalyzing(true);
        setError(null);

        try {
            const payload = { ...features };
            // Convert boolean to actual boolean for API
            if (typeof payload.has_test_changes === "boolean") {
                // Keep it as boolean, the backend handles it
            }

            const result = await predictRisk(payload);
            setPrediction(result);

            toast({
                title: result.risk_label === "high" ? "⚠️ High Risk Detected" : "✅ Low Risk",
                description: `Risk Score: ${(result.risk_score * 100).toFixed(1)}% — Model: ${result.model_version}`,
                variant: result.risk_label === "high" ? "destructive" : "default",
            });
        } catch (err: unknown) {
            const message = err instanceof Error ? err.message : "Failed to connect to the ML API. Make sure the backend is running.";
            setError(message);
            toast({
                title: "Prediction Failed",
                description: message,
                variant: "destructive",
            });
        } finally {
            setIsAnalyzing(false);
        }
    };

    return (
        <div className="flex h-screen bg-background">
            <Sidebar />
            <div className="flex flex-1 flex-col overflow-hidden">
                <Header />

                <main className="flex-1 overflow-y-auto p-6">
                    <div className="mx-auto max-w-7xl">
                        {/* Page Header */}
                        <motion.div
                            initial={{ opacity: 0, y: -20 }}
                            animate={{ opacity: 1, y: 0 }}
                            className="mb-8"
                        >
                            <div className="flex items-center gap-3 mb-2">
                                <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-violet-500/20 to-purple-600/20">
                                    <Brain className="h-5 w-5 text-violet-400" />
                                </div>
                                <div>
                                    <h1 className="text-3xl font-bold text-foreground">
                                        ML Risk Analyzer
                                    </h1>
                                    <p className="text-muted-foreground">
                                        Test the XGBoost model with custom PR features — trained on
                                        800 real GitHub PRs
                                    </p>
                                </div>
                            </div>
                        </motion.div>

                        <div className="grid gap-6 lg:grid-cols-5">
                            {/* Left Panel - Feature Inputs */}
                            <div className="lg:col-span-3 space-y-6">
                                {/* Preset Buttons */}
                                <Card className="border-border/50 bg-card/50 backdrop-blur-sm">
                                    <CardHeader className="pb-3">
                                        <CardTitle className="flex items-center gap-2 text-base">
                                            <Zap className="h-4 w-4 text-amber-400" />
                                            Quick Presets
                                        </CardTitle>
                                        <CardDescription>
                                            Load a predefined scenario to test the model
                                        </CardDescription>
                                    </CardHeader>
                                    <CardContent>
                                        <div className="grid grid-cols-3 gap-3">
                                            <Button
                                                variant="outline"
                                                className="gap-2 border-emerald-500/30 bg-emerald-500/5 hover:bg-emerald-500/10 text-emerald-400"
                                                onClick={() => loadPreset("safe")}
                                            >
                                                <CheckCircle2 className="h-4 w-4" />
                                                Safe PR
                                            </Button>
                                            <Button
                                                variant="outline"
                                                className="gap-2 border-amber-500/30 bg-amber-500/5 hover:bg-amber-500/10 text-amber-400"
                                                onClick={() => loadPreset("borderline")}
                                            >
                                                <AlertTriangle className="h-4 w-4" />
                                                Borderline
                                            </Button>
                                            <Button
                                                variant="outline"
                                                className="gap-2 border-red-500/30 bg-red-500/5 hover:bg-red-500/10 text-red-400"
                                                onClick={() => loadPreset("risky")}
                                            >
                                                <Shield className="h-4 w-4" />
                                                Risky PR
                                            </Button>
                                        </div>
                                    </CardContent>
                                </Card>

                                {/* Feature Inputs */}
                                <Card className="border-border/50 bg-card/50 backdrop-blur-sm">
                                    <CardHeader>
                                        <div className="flex items-center justify-between">
                                            <div>
                                                <CardTitle className="flex items-center gap-2">
                                                    <Sparkles className="h-5 w-5 text-violet-400" />
                                                    PR Features
                                                </CardTitle>
                                                <CardDescription>
                                                    Adjust the 12 features that the XGBoost model uses for
                                                    risk prediction
                                                </CardDescription>
                                            </div>
                                            <Button
                                                variant="ghost"
                                                size="sm"
                                                className="gap-1 text-muted-foreground"
                                                onClick={resetFeatures}
                                            >
                                                <RotateCcw className="h-3.5 w-3.5" />
                                                Reset
                                            </Button>
                                        </div>
                                    </CardHeader>
                                    <CardContent>
                                        <div className="grid gap-4 md:grid-cols-2">
                                            {FEATURES.map((feature) => {
                                                const Icon = feature.icon;
                                                return (
                                                    <TooltipProvider key={feature.key}>
                                                        <Tooltip>
                                                            <TooltipTrigger asChild>
                                                                <div
                                                                    className={cn(
                                                                        "rounded-lg border p-3 transition-all",
                                                                        "border-border/50 hover:border-border"
                                                                    )}
                                                                >
                                                                    <div className="flex items-center gap-2 mb-2">
                                                                        <div className="flex h-7 w-7 items-center justify-center rounded-md bg-muted/50">
                                                                            <Icon className="h-3.5 w-3.5 text-muted-foreground" />
                                                                        </div>
                                                                        <Label className="text-sm font-medium text-foreground cursor-help">
                                                                            {feature.label}
                                                                        </Label>
                                                                        <Info className="h-3 w-3 text-muted-foreground/50 ml-auto" />
                                                                    </div>

                                                                    {feature.type === "number" && (
                                                                        <Input
                                                                            type="number"
                                                                            min={feature.min}
                                                                            max={feature.max}
                                                                            value={features[feature.key] as number}
                                                                            onChange={(e) =>
                                                                                updateFeature(
                                                                                    feature.key,
                                                                                    Number(e.target.value)
                                                                                )
                                                                            }
                                                                            className="h-9 bg-background/50"
                                                                        />
                                                                    )}

                                                                    {feature.type === "slider" && (
                                                                        <div className="flex items-center gap-3">
                                                                            <Slider
                                                                                min={feature.min}
                                                                                max={feature.max}
                                                                                step={feature.step}
                                                                                value={[
                                                                                    features[feature.key] as number,
                                                                                ]}
                                                                                onValueChange={(v) =>
                                                                                    updateFeature(feature.key, v[0])
                                                                                }
                                                                                className="flex-1"
                                                                            />
                                                                            <span className="w-12 text-right font-mono text-sm text-muted-foreground">
                                                                                {(
                                                                                    features[feature.key] as number
                                                                                ).toFixed(2)}
                                                                            </span>
                                                                        </div>
                                                                    )}

                                                                    {feature.type === "toggle" && (
                                                                        <div className="flex items-center justify-between">
                                                                            <span className="text-sm text-muted-foreground">
                                                                                {features[feature.key]
                                                                                    ? "Yes"
                                                                                    : "No"}
                                                                            </span>
                                                                            <Switch
                                                                                checked={
                                                                                    features[feature.key] as boolean
                                                                                }
                                                                                onCheckedChange={(v) =>
                                                                                    updateFeature(feature.key, v)
                                                                                }
                                                                            />
                                                                        </div>
                                                                    )}
                                                                </div>
                                                            </TooltipTrigger>
                                                            <TooltipContent
                                                                side="top"
                                                                className="max-w-xs"
                                                            >
                                                                <p>{feature.description}</p>
                                                            </TooltipContent>
                                                        </Tooltip>
                                                    </TooltipProvider>
                                                );
                                            })}
                                        </div>

                                        {/* Predict Button */}
                                        <div className="mt-6 flex items-center justify-between">
                                            <p className="text-sm text-muted-foreground">
                                                Powered by XGBoost · Trained on 800 real PRs
                                            </p>
                                            <Button
                                                size="lg"
                                                className="gap-2 bg-gradient-to-r from-violet-600 to-purple-600 hover:from-violet-500 hover:to-purple-500 text-white shadow-lg shadow-violet-500/20"
                                                onClick={handlePredict}
                                                disabled={isAnalyzing}
                                            >
                                                {isAnalyzing ? (
                                                    <>
                                                        <Loader2 className="h-4 w-4 animate-spin" />
                                                        Analyzing...
                                                    </>
                                                ) : (
                                                    <>
                                                        <Brain className="h-4 w-4" />
                                                        Predict Risk
                                                    </>
                                                )}
                                            </Button>
                                        </div>
                                    </CardContent>
                                </Card>
                            </div>

                            {/* Right Panel - Results */}
                            <div className="lg:col-span-2 space-y-6">
                                <AnimatePresence mode="wait">
                                    {error && (
                                        <motion.div
                                            initial={{ opacity: 0, scale: 0.95 }}
                                            animate={{ opacity: 1, scale: 1 }}
                                            exit={{ opacity: 0, scale: 0.95 }}
                                        >
                                            <Card className="border-red-500/30 bg-red-500/5">
                                                <CardContent className="pt-6">
                                                    <div className="flex items-start gap-3">
                                                        <AlertTriangle className="h-5 w-5 text-red-400 mt-0.5" />
                                                        <div>
                                                            <p className="font-medium text-red-400">
                                                                Connection Error
                                                            </p>
                                                            <p className="text-sm text-muted-foreground mt-1">
                                                                {error}
                                                            </p>
                                                            <p className="text-xs text-muted-foreground mt-2">
                                                                Make sure the backend is running:
                                                            </p>
                                                            <code className="block mt-1 text-xs bg-background/50 p-2 rounded font-mono">
                                                                cd backend && python -m uvicorn app.main:app
                                                                --port 8000
                                                            </code>
                                                        </div>
                                                    </div>
                                                </CardContent>
                                            </Card>
                                        </motion.div>
                                    )}

                                    {!prediction && !error && (
                                        <motion.div
                                            initial={{ opacity: 0 }}
                                            animate={{ opacity: 1 }}
                                            exit={{ opacity: 0 }}
                                        >
                                            <Card className="border-border/50 bg-card/50 backdrop-blur-sm">
                                                <CardContent className="flex flex-col items-center justify-center py-16">
                                                    <div className="flex h-16 w-16 items-center justify-center rounded-full bg-gradient-to-br from-violet-500/10 to-purple-600/10 mb-4">
                                                        <Cpu className="h-8 w-8 text-violet-400/50" />
                                                    </div>
                                                    <h3 className="text-lg font-semibold text-muted-foreground">
                                                        Ready to Analyze
                                                    </h3>
                                                    <p className="text-sm text-muted-foreground/60 mt-1 text-center max-w-xs">
                                                        Adjust the PR features on the left and click
                                                        "Predict Risk" to see the ML model's assessment
                                                    </p>
                                                </CardContent>
                                            </Card>
                                        </motion.div>
                                    )}

                                    {prediction && (
                                        <motion.div
                                            key="results"
                                            initial={{ opacity: 0, y: 20 }}
                                            animate={{ opacity: 1, y: 0 }}
                                            exit={{ opacity: 0, y: -20 }}
                                            className="space-y-6"
                                        >
                                            {/* Risk Score Card */}
                                            <Card
                                                className={cn(
                                                    "border-2 backdrop-blur-sm overflow-hidden",
                                                    prediction.risk_label === "high"
                                                        ? "border-red-500/40 bg-red-500/5"
                                                        : "border-emerald-500/40 bg-emerald-500/5"
                                                )}
                                            >
                                                <CardContent className="pt-6">
                                                    <div className="text-center">
                                                        {/* Big Risk Circle */}
                                                        <div className="relative mx-auto w-36 h-36 mb-4">
                                                            <svg
                                                                className="w-full h-full -rotate-90"
                                                                viewBox="0 0 100 100"
                                                            >
                                                                <circle
                                                                    cx="50"
                                                                    cy="50"
                                                                    r="42"
                                                                    fill="none"
                                                                    stroke="currentColor"
                                                                    className="text-muted/20"
                                                                    strokeWidth="8"
                                                                />
                                                                <motion.circle
                                                                    cx="50"
                                                                    cy="50"
                                                                    r="42"
                                                                    fill="none"
                                                                    stroke="currentColor"
                                                                    className={
                                                                        prediction.risk_label === "high"
                                                                            ? "text-red-500"
                                                                            : "text-emerald-500"
                                                                    }
                                                                    strokeWidth="8"
                                                                    strokeLinecap="round"
                                                                    strokeDasharray={`${prediction.risk_score * 264} 264`}
                                                                    initial={{ strokeDasharray: "0 264" }}
                                                                    animate={{
                                                                        strokeDasharray: `${prediction.risk_score * 264} 264`,
                                                                    }}
                                                                    transition={{
                                                                        duration: 1,
                                                                        ease: "easeOut",
                                                                    }}
                                                                />
                                                            </svg>
                                                            <div className="absolute inset-0 flex flex-col items-center justify-center">
                                                                <motion.span
                                                                    className={cn(
                                                                        "text-3xl font-bold",
                                                                        prediction.risk_label === "high"
                                                                            ? "text-red-400"
                                                                            : "text-emerald-400"
                                                                    )}
                                                                    initial={{ opacity: 0 }}
                                                                    animate={{ opacity: 1 }}
                                                                    transition={{ delay: 0.5 }}
                                                                >
                                                                    {prediction.risk_percentage.toFixed(1)}%
                                                                </motion.span>
                                                                <span className="text-xs text-muted-foreground">
                                                                    Risk Score
                                                                </span>
                                                            </div>
                                                        </div>

                                                        {/* Verdict Badge */}
                                                        <Badge
                                                            className={cn(
                                                                "text-sm px-4 py-1",
                                                                prediction.risk_label === "high"
                                                                    ? "bg-red-500/20 text-red-400 border-red-500/30"
                                                                    : "bg-emerald-500/20 text-emerald-400 border-emerald-500/30"
                                                            )}
                                                        >
                                                            {prediction.risk_label === "high"
                                                                ? "🔴 HIGH RISK"
                                                                : "🟢 LOW RISK"}
                                                        </Badge>

                                                        {/* Model Info */}
                                                        <div className="mt-4 flex items-center justify-center gap-4 text-xs text-muted-foreground">
                                                            <span className="flex items-center gap-1">
                                                                <Cpu className="h-3 w-3" />
                                                                {prediction.model_version}
                                                            </span>
                                                            <span>•</span>
                                                            <span>
                                                                {prediction.using_fallback
                                                                    ? "⚠️ Fallback"
                                                                    : "✅ Live Model"}
                                                            </span>
                                                        </div>
                                                    </div>
                                                </CardContent>
                                            </Card>

                                            {/* Feature Importance */}
                                            <Card className="border-border/50 bg-card/50 backdrop-blur-sm">
                                                <CardHeader className="pb-3">
                                                    <CardTitle className="flex items-center gap-2 text-base">
                                                        <BarChart3 className="h-4 w-4 text-violet-400" />
                                                        Feature Importance
                                                    </CardTitle>
                                                    <CardDescription>
                                                        How much each feature influenced the prediction
                                                    </CardDescription>
                                                </CardHeader>
                                                <CardContent>
                                                    <div className="space-y-3">
                                                        {Object.entries(prediction.feature_importance)
                                                            .sort(([, a], [, b]) => b - a)
                                                            .map(([name, importance], index) => {
                                                                const pct = (importance * 100).toFixed(1);
                                                                const isTop = index < 3;
                                                                return (
                                                                    <motion.div
                                                                        key={name}
                                                                        initial={{ opacity: 0, x: -10 }}
                                                                        animate={{ opacity: 1, x: 0 }}
                                                                        transition={{ delay: index * 0.05 }}
                                                                    >
                                                                        <div className="flex items-center justify-between text-sm mb-1">
                                                                            <span
                                                                                className={cn(
                                                                                    "capitalize",
                                                                                    isTop
                                                                                        ? "text-foreground font-medium"
                                                                                        : "text-muted-foreground"
                                                                                )}
                                                                            >
                                                                                {name.replace(/_/g, " ")}
                                                                            </span>
                                                                            <span
                                                                                className={cn(
                                                                                    "font-mono text-xs",
                                                                                    isTop
                                                                                        ? "text-violet-400"
                                                                                        : "text-muted-foreground"
                                                                                )}
                                                                            >
                                                                                {pct}%
                                                                            </span>
                                                                        </div>
                                                                        <div className="h-2 rounded-full bg-muted/30 overflow-hidden">
                                                                            <motion.div
                                                                                className={cn(
                                                                                    "h-full rounded-full",
                                                                                    isTop
                                                                                        ? "bg-gradient-to-r from-violet-500 to-purple-500"
                                                                                        : "bg-muted-foreground/30"
                                                                                )}
                                                                                initial={{ width: 0 }}
                                                                                animate={{
                                                                                    width: `${importance * 100}%`,
                                                                                }}
                                                                                transition={{
                                                                                    duration: 0.8,
                                                                                    delay: index * 0.05,
                                                                                }}
                                                                            />
                                                                        </div>
                                                                    </motion.div>
                                                                );
                                                            })}
                                                    </div>

                                                    {/* Explanation */}
                                                    <div className="mt-6 rounded-lg bg-muted/20 p-4">
                                                        <p className="text-xs text-muted-foreground">
                                                            <strong className="text-foreground">
                                                                How it works:
                                                            </strong>{" "}
                                                            The trained XGBoost model analyzes all 12 features
                                                            simultaneously. Features with higher importance
                                                            bars had more influence on this specific
                                                            prediction. The model was trained on 800 real PRs
                                                            from repositories like React, TensorFlow, and
                                                            Kubernetes.
                                                        </p>
                                                    </div>
                                                </CardContent>
                                            </Card>
                                        </motion.div>
                                    )}
                                </AnimatePresence>
                            </div>
                        </div>
                    </div>
                </main>
            </div>
        </div>
    );
}
