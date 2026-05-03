import * as React from "react";
import { cn } from "@/lib/cn";

export const Table = ({ className, ...p }: React.HTMLAttributes<HTMLTableElement>) => (
  <table className={cn("w-full text-sm", className)} {...p} />
);
export const Thead = ({ className, ...p }: React.HTMLAttributes<HTMLTableSectionElement>) => (
  <thead className={cn("border-b border-border-subtle text-fg-muted", className)} {...p} />
);
export const Tr = ({ className, ...p }: React.HTMLAttributes<HTMLTableRowElement>) => (
  <tr className={cn("border-b border-border-subtle/60 last:border-0 hover:bg-bg-2/60 transition-colors", className)} {...p} />
);
export const Th = ({ className, ...p }: React.ThHTMLAttributes<HTMLTableCellElement>) => (
  <th className={cn("text-left text-[11px] font-medium uppercase tracking-wide px-4 py-2.5", className)} {...p} />
);
export const Td = ({ className, ...p }: React.TdHTMLAttributes<HTMLTableCellElement>) => (
  <td className={cn("px-4 py-2.5 text-fg", className)} {...p} />
);
