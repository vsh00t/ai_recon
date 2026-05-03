"use client";

import * as React from "react";
import { Slot } from "@radix-ui/react-slot";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/cn";

const buttonVariants = cva(
  "inline-flex items-center justify-center gap-1.5 rounded-md text-sm font-medium select-none whitespace-nowrap outline-none transition-[background,color,border] duration-100 disabled:opacity-50 disabled:pointer-events-none focus-visible:ring-2 focus-visible:ring-accent/60",
  {
    variants: {
      variant: {
        primary: "bg-accent text-accent-fg hover:bg-accent/90 shadow-sm",
        secondary: "bg-bg-2 text-fg hover:bg-bg-3 border border-border-subtle",
        ghost: "text-fg hover:bg-bg-2",
        outline: "border border-border-strong text-fg hover:bg-bg-2",
        destructive: "bg-sev-critical text-white hover:bg-sev-critical/90",
        link: "text-accent hover:underline px-0",
      },
      size: {
        sm: "h-7 px-2.5 text-xs",
        md: "h-8 px-3",
        lg: "h-10 px-4 text-sm",
        icon: "h-8 w-8",
      },
    },
    defaultVariants: { variant: "primary", size: "md" },
  }
);

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean;
}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, asChild, ...props }, ref) => {
    const Comp = asChild ? Slot : "button";
    return <Comp ref={ref} className={cn(buttonVariants({ variant, size }), className)} {...props} />;
  }
);
Button.displayName = "Button";
