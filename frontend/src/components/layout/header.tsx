import { useState } from "react";
import { Link, useLocation } from "react-router-dom";
import { motion } from "framer-motion";
import {
  Shield,
  Search,
  Bell,
  Menu,
  X,
  ChevronDown,
  Settings,
  LogOut,
  User,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

const navLinks = [
  { href: "/", label: "Dashboard" },
  { href: "/audit-logs", label: "Audit Logs" },
  { href: "/submit", label: "Submit PR" },
  { href: "/settings", label: "Settings" },
];

export function Header() {
  const { pathname } = useLocation();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [searchFocused, setSearchFocused] = useState(false);

  return (
    <header className="sticky top-0 z-50 border-b border-border bg-background/80 backdrop-blur-xl">
      <div className="mx-auto flex h-16 max-w-screen-2xl items-center justify-between px-4 lg:px-8">
        {/* Logo */}
        <Link to="/" className="flex items-center gap-3">
          <motion.div
            className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary/10"
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
          >
            <Shield className="h-5 w-5 text-primary" />
          </motion.div>
          <span className="hidden font-semibold tracking-tight text-foreground sm:block">
            SecureAudit
          </span>
        </Link>

        {/* Desktop Navigation */}
        <nav className="hidden items-center gap-1 md:flex">
          {navLinks.map((link) => {
            const isActive = pathname === link.href;
            return (
              <Link key={link.href} to={link.href}>
                <motion.div
                  className={cn(
                    "relative rounded-lg px-4 py-2 text-sm font-medium transition-colors",
                    isActive
                      ? "text-foreground"
                      : "text-muted-foreground hover:text-foreground"
                  )}
                  whileHover={{ scale: 1.02 }}
                  whileTap={{ scale: 0.98 }}
                >
                  {link.label}
                  {isActive && (
                    <motion.div
                      className="absolute inset-0 rounded-lg bg-secondary"
                      layoutId="nav-indicator"
                      transition={{
                        type: "spring",
                        stiffness: 500,
                        damping: 30,
                      }}
                      style={{ zIndex: -1 }}
                    />
                  )}
                </motion.div>
              </Link>
            );
          })}
        </nav>

        {/* Search & Actions */}
        <div className="flex items-center gap-3">
          {/* Search */}
          <motion.div
            className="relative hidden lg:block"
            animate={{ width: searchFocused ? 280 : 200 }}
            transition={{ duration: 0.2 }}
          >
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              placeholder="Search PRs..."
              className="h-9 bg-secondary/50 pl-9 text-sm"
              onFocus={() => setSearchFocused(true)}
              onBlur={() => setSearchFocused(false)}
            />
            <kbd className="pointer-events-none absolute right-2 top-1/2 hidden -translate-y-1/2 rounded border border-border bg-muted px-1.5 font-mono text-xs text-muted-foreground xl:inline-block">
              /
            </kbd>
          </motion.div>

          {/* Notifications */}
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                variant="ghost"
                size="icon"
                className="relative h-9 w-9"
              >
                <Bell className="h-4 w-4" />
                <Badge className="absolute -right-1 -top-1 h-5 w-5 rounded-full bg-destructive p-0 text-xs text-destructive-foreground">
                  3
                </Badge>
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-80">
              <div className="p-3">
                <h4 className="font-medium">Notifications</h4>
                <p className="text-sm text-muted-foreground">
                  You have 3 unread notifications
                </p>
              </div>
              <DropdownMenuSeparator />
              <DropdownMenuItem className="flex flex-col items-start gap-1 p-3">
                <span className="text-sm font-medium">
                  Critical vulnerability detected
                </span>
                <span className="text-xs text-muted-foreground">
                  PR #1234 in api-gateway - 2 min ago
                </span>
              </DropdownMenuItem>
              <DropdownMenuItem className="flex flex-col items-start gap-1 p-3">
                <span className="text-sm font-medium">Scan completed</span>
                <span className="text-xs text-muted-foreground">
                  PR #1233 approved - 15 min ago
                </span>
              </DropdownMenuItem>
              <DropdownMenuItem className="flex flex-col items-start gap-1 p-3">
                <span className="text-sm font-medium">
                  Blockchain verification
                </span>
                <span className="text-xs text-muted-foreground">
                  Audit record confirmed - 1 hour ago
                </span>
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>

          {/* User Menu */}
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                variant="ghost"
                className="hidden h-9 gap-2 px-2 md:flex"
              >
                <Avatar className="h-7 w-7">
                  <AvatarImage src="https://api.dicebear.com/7.x/initials/svg?seed=JD" />
                  <AvatarFallback>JD</AvatarFallback>
                </Avatar>
                <span className="text-sm font-medium">John Doe</span>
                <ChevronDown className="h-4 w-4 text-muted-foreground" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-56">
              <div className="p-2">
                <p className="font-medium">John Doe</p>
                <p className="text-sm text-muted-foreground">
                  john@acme-corp.com
                </p>
              </div>
              <DropdownMenuSeparator />
              <DropdownMenuItem>
                <User className="mr-2 h-4 w-4" />
                Profile
              </DropdownMenuItem>
              <DropdownMenuItem>
                <Settings className="mr-2 h-4 w-4" />
                Settings
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem className="text-destructive">
                <LogOut className="mr-2 h-4 w-4" />
                Log out
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>

          {/* Mobile Menu Toggle */}
          <Button
            variant="ghost"
            size="icon"
            className="md:hidden"
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
          >
            {mobileMenuOpen ? (
              <X className="h-5 w-5" />
            ) : (
              <Menu className="h-5 w-5" />
            )}
          </Button>
        </div>
      </div>

      {/* Mobile Menu */}
      {mobileMenuOpen && (
        <motion.div
          initial={{ opacity: 0, height: 0 }}
          animate={{ opacity: 1, height: "auto" }}
          exit={{ opacity: 0, height: 0 }}
          className="border-t border-border md:hidden"
        >
          <nav className="flex flex-col p-4">
            {navLinks.map((link) => (
              <Link
                key={link.href}
                to={link.href}
                onClick={() => setMobileMenuOpen(false)}
                className={cn(
                  "rounded-lg px-4 py-3 text-sm font-medium transition-colors",
                  pathname === link.href
                    ? "bg-secondary text-foreground"
                    : "text-muted-foreground hover:bg-secondary/50 hover:text-foreground"
                )}
              >
                {link.label}
              </Link>
            ))}
          </nav>
        </motion.div>
      )}
    </header>
  );
}
