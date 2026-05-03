"use client";
import * as React from "react";
import { cn } from "@/lib/cn";

export const Input = React.forwardRef<HTMLInputElement, React.InputHTMLAttributes<HTMLInputElement>>(
  ({ className, ...props }, ref) => (
    <input
      ref={ref}
      className={cn(
        "h-9 w-full rounded-md border border-border-subtle bg-bg-1 px-3 text-sm text-fg",
        "placeholder:text-fg-muted outline-none transition-colors",
        "focus:border-accent focus:ring-2 focus:ring-accent/30",
        "disabled:opacity-50",
        className,
      )}
      {...props}
    />
  ),
);
Input.displayName = "Input";
