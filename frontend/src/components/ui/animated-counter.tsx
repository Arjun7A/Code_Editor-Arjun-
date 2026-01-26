"use client";

import { useEffect, useRef, useState } from "react";
import { motion, useSpring, useTransform } from "framer-motion";

interface AnimatedCounterProps {
  value: number;
  duration?: number;
  className?: string;
  formatFn?: (value: number) => string;
}

export function AnimatedCounter({
  value,
  duration = 1,
  className,
  formatFn = (v) => Math.round(v).toLocaleString(),
}: AnimatedCounterProps) {
  const spring = useSpring(0, { duration: duration * 1000 });
  const display = useTransform(spring, (latest) => formatFn(latest));
  const [displayValue, setDisplayValue] = useState(formatFn(0));

  useEffect(() => {
    spring.set(value);
  }, [spring, value]);

  useEffect(() => {
    const unsubscribe = display.on("change", (latest) => {
      setDisplayValue(latest);
    });
    return unsubscribe;
  }, [display]);

  return (
    <motion.span className={className} aria-label={formatFn(value)}>
      {displayValue}
    </motion.span>
  );
}
