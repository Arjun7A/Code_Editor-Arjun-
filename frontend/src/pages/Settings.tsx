import { useState } from "react";
import { Header } from "@/components/layout/header";
import { Sidebar } from "@/components/layout/sidebar";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
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
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { useToast } from "@/hooks/use-toast";
import {
  Settings,
  Shield,
  Bell,
  Link2,
  Key,
  Brain,
  Code,
  GitBranch,
  Globe,
  Mail,
  Slack,
  Webhook,
  Database,
  Lock,
  CheckCircle2,
  AlertTriangle,
  Plus,
  Trash2,
  Copy,
  Eye,
  EyeOff,
  RefreshCw,
  Save,
} from "lucide-react";
import { cn } from "@/lib/utils";

export default function SettingsPage() {
  const { toast } = useToast();
  const [showApiKey, setShowApiKey] = useState(false);
  const [isSaving, setIsSaving] = useState(false);

  const [generalSettings, setGeneralSettings] = useState({
    organizationName: "Acme Corporation",
    defaultBranch: "main",
    timezone: "UTC",
    language: "en",
    autoAnalyze: true,
    requireApproval: true,
    blockOnCritical: true,
  });

  const [securitySettings, setSecuritySettings] = useState({
    minRiskThreshold: "medium",
    enableSAST: true,
    enableSecretsScan: true,
    enableDependencyCheck: true,
    enableLicenseCheck: true,
    scanTimeout: 300,
    maxConcurrentScans: 5,
  });

  const [aiSettings, setAiSettings] = useState({
    enableAI: true,
    model: "gpt-4-turbo",
    temperature: 0.3,
    contextLength: 8192,
    enableAutoSuggestions: true,
    enableCodeExplanation: true,
  });

  const [notifications, setNotifications] = useState({
    emailEnabled: true,
    emailAddress: "security@acme.com",
    slackEnabled: true,
    slackWebhook: "https://hooks.slack.com/services/xxx/yyy/zzz",
    webhookEnabled: false,
    webhookUrl: "",
    notifyOnCritical: true,
    notifyOnHigh: true,
    notifyOnMedium: false,
    notifyOnLow: false,
    dailyDigest: true,
    weeklyReport: true,
  });

  const [integrations] = useState([
    {
      name: "GitHub",
      icon: <GitBranch className="h-5 w-5" />,
      status: "connected",
      account: "acme-corp",
    },
    {
      name: "GitLab",
      icon: <GitBranch className="h-5 w-5" />,
      status: "disconnected",
      account: null,
    },
    {
      name: "Slack",
      icon: <Slack className="h-5 w-5" />,
      status: "connected",
      account: "#security-alerts",
    },
    {
      name: "Jira",
      icon: <Database className="h-5 w-5" />,
      status: "connected",
      account: "ACME Project",
    },
  ]);

  const [apiKeys] = useState([
    {
      id: "1",
      name: "Production API Key",
      prefix: "sk_live_***",
      created: "2024-01-15",
      lastUsed: "2024-01-20",
    },
    {
      id: "2",
      name: "Development API Key",
      prefix: "sk_dev_***",
      created: "2024-01-10",
      lastUsed: "2024-01-19",
    },
  ]);

  const handleSave = async () => {
    setIsSaving(true);
    await new Promise((r) => setTimeout(r, 1000));
    setIsSaving(false);
    toast({
      title: "Settings Saved",
      description: "Your settings have been updated successfully",
    });
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast({
      title: "Copied",
      description: "Copied to clipboard",
    });
  };

  return (
    <div className="flex h-screen bg-background">
      <Sidebar />

      <div className="flex flex-1 flex-col overflow-hidden">
        <Header />

        <main className="flex-1 overflow-y-auto p-6">
          <div className="mx-auto max-w-5xl">
            {/* Header */}
            <div className="mb-8 flex items-center justify-between">
              <div>
                <h1 className="text-3xl font-bold text-foreground">Settings</h1>
                <p className="mt-2 text-muted-foreground">
                  Manage your organization settings, integrations, and
                  preferences
                </p>
              </div>
              <Button
                onClick={handleSave}
                disabled={isSaving}
                className="gap-2"
              >
                {isSaving ? (
                  <RefreshCw className="h-4 w-4 animate-spin" />
                ) : (
                  <Save className="h-4 w-4" />
                )}
                Save Changes
              </Button>
            </div>

            <Tabs defaultValue="general" className="space-y-6">
              <TabsList className="grid w-full grid-cols-6 bg-muted/30">
                <TabsTrigger value="general" className="gap-2">
                  <Settings className="h-4 w-4" />
                  <span className="hidden md:inline">General</span>
                </TabsTrigger>
                <TabsTrigger value="security" className="gap-2">
                  <Shield className="h-4 w-4" />
                  <span className="hidden md:inline">Security</span>
                </TabsTrigger>
                <TabsTrigger value="ai" className="gap-2">
                  <Brain className="h-4 w-4" />
                  <span className="hidden md:inline">AI</span>
                </TabsTrigger>
                <TabsTrigger value="notifications" className="gap-2">
                  <Bell className="h-4 w-4" />
                  <span className="hidden md:inline">Notifications</span>
                </TabsTrigger>
                <TabsTrigger value="integrations" className="gap-2">
                  <Link2 className="h-4 w-4" />
                  <span className="hidden md:inline">Integrations</span>
                </TabsTrigger>
                <TabsTrigger value="api" className="gap-2">
                  <Key className="h-4 w-4" />
                  <span className="hidden md:inline">API Keys</span>
                </TabsTrigger>
              </TabsList>

              {/* General Settings */}
              <TabsContent value="general" className="space-y-6">
                <Card className="border-border/50 bg-card/50 backdrop-blur-sm">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Globe className="h-5 w-5 text-primary" />
                      Organization Settings
                    </CardTitle>
                    <CardDescription>
                      Configure your organization preferences
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-6">
                    <div className="grid gap-4 md:grid-cols-2">
                      <div className="space-y-2">
                        <Label htmlFor="orgName">Organization Name</Label>
                        <Input
                          id="orgName"
                          value={generalSettings.organizationName}
                          onChange={(e) =>
                            setGeneralSettings({
                              ...generalSettings,
                              organizationName: e.target.value,
                            })
                          }
                        />
                      </div>
                      <div className="space-y-2">
                        <Label htmlFor="defaultBranch">Default Branch</Label>
                        <Input
                          id="defaultBranch"
                          value={generalSettings.defaultBranch}
                          onChange={(e) =>
                            setGeneralSettings({
                              ...generalSettings,
                              defaultBranch: e.target.value,
                            })
                          }
                        />
                      </div>
                    </div>

                    <div className="grid gap-4 md:grid-cols-2">
                      <div className="space-y-2">
                        <Label htmlFor="timezone">Timezone</Label>
                        <Select
                          value={generalSettings.timezone}
                          onValueChange={(value) =>
                            setGeneralSettings({
                              ...generalSettings,
                              timezone: value,
                            })
                          }
                        >
                          <SelectTrigger id="timezone">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="UTC">UTC</SelectItem>
                            <SelectItem value="America/New_York">
                              Eastern Time
                            </SelectItem>
                            <SelectItem value="America/Los_Angeles">
                              Pacific Time
                            </SelectItem>
                            <SelectItem value="Europe/London">
                              London
                            </SelectItem>
                            <SelectItem value="Asia/Tokyo">Tokyo</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                      <div className="space-y-2">
                        <Label htmlFor="language">Language</Label>
                        <Select
                          value={generalSettings.language}
                          onValueChange={(value) =>
                            setGeneralSettings({
                              ...generalSettings,
                              language: value,
                            })
                          }
                        >
                          <SelectTrigger id="language">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="en">English</SelectItem>
                            <SelectItem value="es">Spanish</SelectItem>
                            <SelectItem value="fr">French</SelectItem>
                            <SelectItem value="de">German</SelectItem>
                            <SelectItem value="ja">Japanese</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                    </div>
                  </CardContent>
                </Card>

                <Card className="border-border/50 bg-card/50 backdrop-blur-sm">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Code className="h-5 w-5 text-primary" />
                      Analysis Behavior
                    </CardTitle>
                    <CardDescription>
                      Control how PRs are analyzed and processed
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="flex items-center justify-between rounded-lg border border-border/50 p-4">
                      <div>
                        <p className="font-medium text-foreground">
                          Auto-analyze new PRs
                        </p>
                        <p className="text-sm text-muted-foreground">
                          Automatically start analysis when a new PR is detected
                        </p>
                      </div>
                      <Switch
                        checked={generalSettings.autoAnalyze}
                        onCheckedChange={(checked) =>
                          setGeneralSettings({
                            ...generalSettings,
                            autoAnalyze: checked,
                          })
                        }
                      />
                    </div>

                    <div className="flex items-center justify-between rounded-lg border border-border/50 p-4">
                      <div>
                        <p className="font-medium text-foreground">
                          Require approval for merge
                        </p>
                        <p className="text-sm text-muted-foreground">
                          Require security approval before PRs can be merged
                        </p>
                      </div>
                      <Switch
                        checked={generalSettings.requireApproval}
                        onCheckedChange={(checked) =>
                          setGeneralSettings({
                            ...generalSettings,
                            requireApproval: checked,
                          })
                        }
                      />
                    </div>

                    <div className="flex items-center justify-between rounded-lg border border-critical/20 bg-critical/5 p-4">
                      <div>
                        <p className="font-medium text-foreground">
                          Block merge on critical issues
                        </p>
                        <p className="text-sm text-muted-foreground">
                          Prevent merging PRs with critical security findings
                        </p>
                      </div>
                      <Switch
                        checked={generalSettings.blockOnCritical}
                        onCheckedChange={(checked) =>
                          setGeneralSettings({
                            ...generalSettings,
                            blockOnCritical: checked,
                          })
                        }
                      />
                    </div>
                  </CardContent>
                </Card>
              </TabsContent>

              {/* Security Settings */}
              <TabsContent value="security" className="space-y-6">
                <Card className="border-border/50 bg-card/50 backdrop-blur-sm">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Shield className="h-5 w-5 text-primary" />
                      Security Scanning
                    </CardTitle>
                    <CardDescription>
                      Configure security scanning options
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-6">
                    <div className="space-y-2">
                      <Label htmlFor="minRisk">Minimum Risk Threshold</Label>
                      <Select
                        value={securitySettings.minRiskThreshold}
                        onValueChange={(value) =>
                          setSecuritySettings({
                            ...securitySettings,
                            minRiskThreshold: value,
                          })
                        }
                      >
                        <SelectTrigger id="minRisk">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="low">Low and above</SelectItem>
                          <SelectItem value="medium">
                            Medium and above
                          </SelectItem>
                          <SelectItem value="high">High and above</SelectItem>
                          <SelectItem value="critical">Critical only</SelectItem>
                        </SelectContent>
                      </Select>
                      <p className="text-xs text-muted-foreground">
                        Only report findings at or above this severity level
                      </p>
                    </div>

                    <Separator />

                    <div className="grid gap-4 md:grid-cols-2">
                      <div className="flex items-center justify-between rounded-lg border border-border/50 p-4">
                        <div className="flex items-center gap-3">
                          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary/10">
                            <Code className="h-4 w-4 text-primary" />
                          </div>
                          <div>
                            <p className="font-medium text-foreground">
                              SAST Scanning
                            </p>
                            <p className="text-xs text-muted-foreground">
                              Static analysis
                            </p>
                          </div>
                        </div>
                        <Switch
                          checked={securitySettings.enableSAST}
                          onCheckedChange={(checked) =>
                            setSecuritySettings({
                              ...securitySettings,
                              enableSAST: checked,
                            })
                          }
                        />
                      </div>

                      <div className="flex items-center justify-between rounded-lg border border-border/50 p-4">
                        <div className="flex items-center gap-3">
                          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-warning/10">
                            <Key className="h-4 w-4 text-warning" />
                          </div>
                          <div>
                            <p className="font-medium text-foreground">
                              Secrets Detection
                            </p>
                            <p className="text-xs text-muted-foreground">
                              API keys, tokens
                            </p>
                          </div>
                        </div>
                        <Switch
                          checked={securitySettings.enableSecretsScan}
                          onCheckedChange={(checked) =>
                            setSecuritySettings({
                              ...securitySettings,
                              enableSecretsScan: checked,
                            })
                          }
                        />
                      </div>

                      <div className="flex items-center justify-between rounded-lg border border-border/50 p-4">
                        <div className="flex items-center gap-3">
                          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-critical/10">
                            <Database className="h-4 w-4 text-critical" />
                          </div>
                          <div>
                            <p className="font-medium text-foreground">
                              Dependency Check
                            </p>
                            <p className="text-xs text-muted-foreground">
                              CVE scanning
                            </p>
                          </div>
                        </div>
                        <Switch
                          checked={securitySettings.enableDependencyCheck}
                          onCheckedChange={(checked) =>
                            setSecuritySettings({
                              ...securitySettings,
                              enableDependencyCheck: checked,
                            })
                          }
                        />
                      </div>

                      <div className="flex items-center justify-between rounded-lg border border-border/50 p-4">
                        <div className="flex items-center gap-3">
                          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-success/10">
                            <Lock className="h-4 w-4 text-success" />
                          </div>
                          <div>
                            <p className="font-medium text-foreground">
                              License Check
                            </p>
                            <p className="text-xs text-muted-foreground">
                              Compliance scan
                            </p>
                          </div>
                        </div>
                        <Switch
                          checked={securitySettings.enableLicenseCheck}
                          onCheckedChange={(checked) =>
                            setSecuritySettings({
                              ...securitySettings,
                              enableLicenseCheck: checked,
                            })
                          }
                        />
                      </div>
                    </div>

                    <Separator />

                    <div className="grid gap-4 md:grid-cols-2">
                      <div className="space-y-2">
                        <Label htmlFor="timeout">Scan Timeout (seconds)</Label>
                        <Input
                          id="timeout"
                          type="number"
                          value={securitySettings.scanTimeout}
                          onChange={(e) =>
                            setSecuritySettings({
                              ...securitySettings,
                              scanTimeout: parseInt(e.target.value),
                            })
                          }
                        />
                      </div>
                      <div className="space-y-2">
                        <Label htmlFor="concurrent">Max Concurrent Scans</Label>
                        <Input
                          id="concurrent"
                          type="number"
                          value={securitySettings.maxConcurrentScans}
                          onChange={(e) =>
                            setSecuritySettings({
                              ...securitySettings,
                              maxConcurrentScans: parseInt(e.target.value),
                            })
                          }
                        />
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </TabsContent>

              {/* AI Settings */}
              <TabsContent value="ai" className="space-y-6">
                <Card className="border-border/50 bg-card/50 backdrop-blur-sm">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Brain className="h-5 w-5 text-primary" />
                      AI Configuration
                    </CardTitle>
                    <CardDescription>
                      Configure AI-powered analysis settings
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-6">
                    <div className="flex items-center justify-between rounded-lg border border-primary/20 bg-primary/5 p-4">
                      <div>
                        <p className="font-medium text-foreground">
                          Enable AI Analysis
                        </p>
                        <p className="text-sm text-muted-foreground">
                          Use AI for code review and security analysis
                        </p>
                      </div>
                      <Switch
                        checked={aiSettings.enableAI}
                        onCheckedChange={(checked) =>
                          setAiSettings({ ...aiSettings, enableAI: checked })
                        }
                      />
                    </div>

                    <div className="grid gap-4 md:grid-cols-2">
                      <div className="space-y-2">
                        <Label htmlFor="model">AI Model</Label>
                        <Select
                          value={aiSettings.model}
                          onValueChange={(value) =>
                            setAiSettings({ ...aiSettings, model: value })
                          }
                          disabled={!aiSettings.enableAI}
                        >
                          <SelectTrigger id="model">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="gpt-4-turbo">
                              GPT-4 Turbo
                            </SelectItem>
                            <SelectItem value="gpt-4">GPT-4</SelectItem>
                            <SelectItem value="gpt-3.5-turbo">
                              GPT-3.5 Turbo
                            </SelectItem>
                            <SelectItem value="claude-3-opus">
                              Claude 3 Opus
                            </SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                      <div className="space-y-2">
                        <Label htmlFor="contextLength">
                          Context Length (tokens)
                        </Label>
                        <Select
                          value={aiSettings.contextLength.toString()}
                          onValueChange={(value) =>
                            setAiSettings({
                              ...aiSettings,
                              contextLength: parseInt(value),
                            })
                          }
                          disabled={!aiSettings.enableAI}
                        >
                          <SelectTrigger id="contextLength">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="4096">4,096</SelectItem>
                            <SelectItem value="8192">8,192</SelectItem>
                            <SelectItem value="16384">16,384</SelectItem>
                            <SelectItem value="32768">32,768</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="temperature">
                        Temperature: {aiSettings.temperature}
                      </Label>
                      <input
                        id="temperature"
                        type="range"
                        min="0"
                        max="1"
                        step="0.1"
                        value={aiSettings.temperature}
                        onChange={(e) =>
                          setAiSettings({
                            ...aiSettings,
                            temperature: parseFloat(e.target.value),
                          })
                        }
                        disabled={!aiSettings.enableAI}
                        className="w-full accent-primary"
                      />
                      <p className="text-xs text-muted-foreground">
                        Lower values produce more focused, deterministic
                        responses
                      </p>
                    </div>

                    <Separator />

                    <div className="space-y-4">
                      <div className="flex items-center justify-between rounded-lg border border-border/50 p-4">
                        <div>
                          <p className="font-medium text-foreground">
                            Auto-suggestions
                          </p>
                          <p className="text-sm text-muted-foreground">
                            Provide AI-generated fix suggestions
                          </p>
                        </div>
                        <Switch
                          checked={aiSettings.enableAutoSuggestions}
                          onCheckedChange={(checked) =>
                            setAiSettings({
                              ...aiSettings,
                              enableAutoSuggestions: checked,
                            })
                          }
                          disabled={!aiSettings.enableAI}
                        />
                      </div>

                      <div className="flex items-center justify-between rounded-lg border border-border/50 p-4">
                        <div>
                          <p className="font-medium text-foreground">
                            Code explanations
                          </p>
                          <p className="text-sm text-muted-foreground">
                            Generate natural language explanations
                          </p>
                        </div>
                        <Switch
                          checked={aiSettings.enableCodeExplanation}
                          onCheckedChange={(checked) =>
                            setAiSettings({
                              ...aiSettings,
                              enableCodeExplanation: checked,
                            })
                          }
                          disabled={!aiSettings.enableAI}
                        />
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </TabsContent>

              {/* Notifications Settings */}
              <TabsContent value="notifications" className="space-y-6">
                <Card className="border-border/50 bg-card/50 backdrop-blur-sm">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Bell className="h-5 w-5 text-primary" />
                      Notification Channels
                    </CardTitle>
                    <CardDescription>
                      Configure where you receive notifications
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-6">
                    {/* Email */}
                    <div className="rounded-lg border border-border/50 p-4">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
                            <Mail className="h-5 w-5 text-primary" />
                          </div>
                          <div>
                            <p className="font-medium text-foreground">Email</p>
                            <p className="text-sm text-muted-foreground">
                              Receive alerts via email
                            </p>
                          </div>
                        </div>
                        <Switch
                          checked={notifications.emailEnabled}
                          onCheckedChange={(checked) =>
                            setNotifications({
                              ...notifications,
                              emailEnabled: checked,
                            })
                          }
                        />
                      </div>
                      {notifications.emailEnabled && (
                        <div className="mt-4 space-y-2">
                          <Label htmlFor="email">Email Address</Label>
                          <Input
                            id="email"
                            type="email"
                            value={notifications.emailAddress}
                            onChange={(e) =>
                              setNotifications({
                                ...notifications,
                                emailAddress: e.target.value,
                              })
                            }
                          />
                        </div>
                      )}
                    </div>

                    {/* Slack */}
                    <div className="rounded-lg border border-border/50 p-4">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-[#4A154B]/10">
                            <Slack className="h-5 w-5 text-[#4A154B]" />
                          </div>
                          <div>
                            <p className="font-medium text-foreground">Slack</p>
                            <p className="text-sm text-muted-foreground">
                              Send alerts to Slack channel
                            </p>
                          </div>
                        </div>
                        <Switch
                          checked={notifications.slackEnabled}
                          onCheckedChange={(checked) =>
                            setNotifications({
                              ...notifications,
                              slackEnabled: checked,
                            })
                          }
                        />
                      </div>
                      {notifications.slackEnabled && (
                        <div className="mt-4 space-y-2">
                          <Label htmlFor="slack">Webhook URL</Label>
                          <Input
                            id="slack"
                            value={notifications.slackWebhook}
                            onChange={(e) =>
                              setNotifications({
                                ...notifications,
                                slackWebhook: e.target.value,
                              })
                            }
                          />
                        </div>
                      )}
                    </div>

                    {/* Custom Webhook */}
                    <div className="rounded-lg border border-border/50 p-4">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-accent/10">
                            <Webhook className="h-5 w-5 text-accent" />
                          </div>
                          <div>
                            <p className="font-medium text-foreground">
                              Custom Webhook
                            </p>
                            <p className="text-sm text-muted-foreground">
                              Send to custom endpoint
                            </p>
                          </div>
                        </div>
                        <Switch
                          checked={notifications.webhookEnabled}
                          onCheckedChange={(checked) =>
                            setNotifications({
                              ...notifications,
                              webhookEnabled: checked,
                            })
                          }
                        />
                      </div>
                      {notifications.webhookEnabled && (
                        <div className="mt-4 space-y-2">
                          <Label htmlFor="webhook">Webhook URL</Label>
                          <Input
                            id="webhook"
                            placeholder="https://api.example.com/webhook"
                            value={notifications.webhookUrl}
                            onChange={(e) =>
                              setNotifications({
                                ...notifications,
                                webhookUrl: e.target.value,
                              })
                            }
                          />
                        </div>
                      )}
                    </div>
                  </CardContent>
                </Card>

                <Card className="border-border/50 bg-card/50 backdrop-blur-sm">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <AlertTriangle className="h-5 w-5 text-warning" />
                      Notification Triggers
                    </CardTitle>
                    <CardDescription>
                      Choose which events trigger notifications
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="grid gap-4 md:grid-cols-2">
                      <div className="flex items-center justify-between rounded-lg border border-critical/20 bg-critical/5 p-4">
                        <span className="font-medium text-foreground">
                          Critical findings
                        </span>
                        <Switch
                          checked={notifications.notifyOnCritical}
                          onCheckedChange={(checked) =>
                            setNotifications({
                              ...notifications,
                              notifyOnCritical: checked,
                            })
                          }
                        />
                      </div>
                      <div className="flex items-center justify-between rounded-lg border border-warning/20 bg-warning/5 p-4">
                        <span className="font-medium text-foreground">
                          High findings
                        </span>
                        <Switch
                          checked={notifications.notifyOnHigh}
                          onCheckedChange={(checked) =>
                            setNotifications({
                              ...notifications,
                              notifyOnHigh: checked,
                            })
                          }
                        />
                      </div>
                      <div className="flex items-center justify-between rounded-lg border border-primary/20 bg-primary/5 p-4">
                        <span className="font-medium text-foreground">
                          Medium findings
                        </span>
                        <Switch
                          checked={notifications.notifyOnMedium}
                          onCheckedChange={(checked) =>
                            setNotifications({
                              ...notifications,
                              notifyOnMedium: checked,
                            })
                          }
                        />
                      </div>
                      <div className="flex items-center justify-between rounded-lg border border-border/50 p-4">
                        <span className="font-medium text-foreground">
                          Low findings
                        </span>
                        <Switch
                          checked={notifications.notifyOnLow}
                          onCheckedChange={(checked) =>
                            setNotifications({
                              ...notifications,
                              notifyOnLow: checked,
                            })
                          }
                        />
                      </div>
                    </div>

                    <Separator />

                    <div className="flex items-center justify-between rounded-lg border border-border/50 p-4">
                      <div>
                        <p className="font-medium text-foreground">
                          Daily digest
                        </p>
                        <p className="text-sm text-muted-foreground">
                          Summary of all findings sent daily
                        </p>
                      </div>
                      <Switch
                        checked={notifications.dailyDigest}
                        onCheckedChange={(checked) =>
                          setNotifications({
                            ...notifications,
                            dailyDigest: checked,
                          })
                        }
                      />
                    </div>

                    <div className="flex items-center justify-between rounded-lg border border-border/50 p-4">
                      <div>
                        <p className="font-medium text-foreground">
                          Weekly report
                        </p>
                        <p className="text-sm text-muted-foreground">
                          Comprehensive weekly security report
                        </p>
                      </div>
                      <Switch
                        checked={notifications.weeklyReport}
                        onCheckedChange={(checked) =>
                          setNotifications({
                            ...notifications,
                            weeklyReport: checked,
                          })
                        }
                      />
                    </div>
                  </CardContent>
                </Card>
              </TabsContent>

              {/* Integrations */}
              <TabsContent value="integrations" className="space-y-6">
                <Card className="border-border/50 bg-card/50 backdrop-blur-sm">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Link2 className="h-5 w-5 text-primary" />
                      Connected Services
                    </CardTitle>
                    <CardDescription>
                      Manage integrations with external services
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    {integrations.map((integration, index) => (
                      <div
                        key={index}
                        className="flex items-center justify-between rounded-lg border border-border/50 p-4"
                      >
                        <div className="flex items-center gap-4">
                          <div
                            className={cn(
                              "flex h-12 w-12 items-center justify-center rounded-lg",
                              integration.status === "connected"
                                ? "bg-success/10 text-success"
                                : "bg-muted text-muted-foreground"
                            )}
                          >
                            {integration.icon}
                          </div>
                          <div>
                            <p className="font-medium text-foreground">
                              {integration.name}
                            </p>
                            {integration.account ? (
                              <p className="text-sm text-muted-foreground">
                                {integration.account}
                              </p>
                            ) : (
                              <p className="text-sm text-muted-foreground">
                                Not connected
                              </p>
                            )}
                          </div>
                        </div>
                        <div className="flex items-center gap-3">
                          <Badge
                            variant={
                              integration.status === "connected"
                                ? "default"
                                : "secondary"
                            }
                            className={cn(
                              integration.status === "connected" &&
                                "bg-success/20 text-success border-success/30"
                            )}
                          >
                            {integration.status === "connected" ? (
                              <span className="flex items-center gap-1">
                                <CheckCircle2 className="h-3 w-3" />
                                Connected
                              </span>
                            ) : (
                              "Disconnected"
                            )}
                          </Badge>
                          <Button
                            variant={
                              integration.status === "connected"
                                ? "outline"
                                : "default"
                            }
                            size="sm"
                          >
                            {integration.status === "connected"
                              ? "Configure"
                              : "Connect"}
                          </Button>
                        </div>
                      </div>
                    ))}

                    <Button variant="outline" className="w-full gap-2 bg-transparent">
                      <Plus className="h-4 w-4" />
                      Add Integration
                    </Button>
                  </CardContent>
                </Card>
              </TabsContent>

              {/* API Keys */}
              <TabsContent value="api" className="space-y-6">
                <Card className="border-border/50 bg-card/50 backdrop-blur-sm">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Key className="h-5 w-5 text-primary" />
                      API Keys
                    </CardTitle>
                    <CardDescription>
                      Manage API keys for programmatic access
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    {apiKeys.map((key) => (
                      <div
                        key={key.id}
                        className="flex items-center justify-between rounded-lg border border-border/50 p-4"
                      >
                        <div className="flex items-center gap-4">
                          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
                            <Key className="h-5 w-5 text-primary" />
                          </div>
                          <div>
                            <p className="font-medium text-foreground">
                              {key.name}
                            </p>
                            <div className="flex items-center gap-2 text-sm text-muted-foreground">
                              <code className="rounded bg-muted px-2 py-0.5 font-mono text-xs">
                                {showApiKey
                                  ? "sk_live_abc123def456..."
                                  : key.prefix}
                              </code>
                            </div>
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          <div className="text-right text-xs text-muted-foreground">
                            <p>Created: {key.created}</p>
                            <p>Last used: {key.lastUsed}</p>
                          </div>
                          <Button
                            variant="ghost"
                            size="icon"
                            onClick={() => setShowApiKey(!showApiKey)}
                          >
                            {showApiKey ? (
                              <EyeOff className="h-4 w-4" />
                            ) : (
                              <Eye className="h-4 w-4" />
                            )}
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon"
                            onClick={() => copyToClipboard(key.prefix)}
                          >
                            <Copy className="h-4 w-4" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="text-destructive hover:text-destructive"
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </div>
                      </div>
                    ))}

                    <Button className="w-full gap-2">
                      <Plus className="h-4 w-4" />
                      Generate New API Key
                    </Button>
                  </CardContent>
                </Card>

                <Card className="border-warning/20 bg-warning/5">
                  <CardContent className="flex items-start gap-4 pt-6">
                    <AlertTriangle className="mt-0.5 h-5 w-5 text-warning" />
                    <div>
                      <p className="font-medium text-foreground">
                        Keep your API keys secure
                      </p>
                      <p className="text-sm text-muted-foreground">
                        Never share your API keys or commit them to source
                        control. If you believe a key has been compromised,
                        regenerate it immediately.
                      </p>
                    </div>
                  </CardContent>
                </Card>
              </TabsContent>
            </Tabs>
          </div>
        </main>
      </div>
    </div>
  );
}
