import { describe, expect, it } from "vitest";
import { type Permission, type Role } from "@/core/auth/types";
import { PermissionDiffEngine } from "../permissionDiff";

describe("Issue #407: Permission-Diff Preview Before Policy Changes", () => {
  const maintainerContext = { role: "maintainer" as const, userId: "admin-satoshi" };
  const viewerContext = { role: "viewer" as const, userId: "user-alice" };

  const basePermissions: Record<Role, Permission[]> = {
    viewer: ["view:tools", "view:dashboard"],
    maintainer: [
      "view:tools",
      "view:dashboard",
      "admin:health",
      "admin:recovery",
      "admin:metrics",
      "admin:replay"
    ],
    service: ["admin:health", "admin:metrics"]
  };

  describe("normal path", () => {
    it("generates an accurate preview of proposed policy additions and removals", () => {
      const proposed: Record<Role, Permission[]> = {
        ...basePermissions,
        service: ["admin:health", "view:tools"] // removed admin:metrics, added view:tools
      };

      const res = PermissionDiffEngine.generateDiffReport(basePermissions, proposed, {
        caller: maintainerContext
      });

      expect(res.ok).toBe(true);
      if (!res.ok) return;

      const report = res.value;
      expect(report.totalAddedCount).toBe(1);
      expect(report.totalRemovedCount).toBe(1);
      expect(report.hasPrivilegeEscalation).toBe(true);
      expect(report.hasPrivilegeRevocation).toBe(true);
      expect(report.recommendedAction).toBe("proceed");
      expect(report.executionPlan.allowApply).toBe(true);

      const serviceDiff = report.roleDiffs.find((d) => d.role === "service");
      expect(serviceDiff?.addedPermissions).toEqual(["view:tools"]);
      expect(serviceDiff?.removedPermissions).toEqual(["admin:metrics"]);
      expect(serviceDiff?.unchangedPermissions).toEqual(["admin:health"]);
      expect(serviceDiff?.netChange).toBe(0);

      // Verify rollback snapshot matches base permissions exactly
      expect(report.rollbackSnapshot).toEqual(basePermissions);
    });

    it("applies policy change atomically returning updated permissions and snapshot", () => {
      const proposed: Record<Role, Permission[]> = {
        ...basePermissions,
        viewer: ["view:tools"] // removed view:dashboard
      };

      const res = PermissionDiffEngine.applyRolePolicyChange(basePermissions, proposed, {
        caller: maintainerContext
      });

      expect(res.ok).toBe(true);
      if (!res.ok) return;

      expect(res.value.newPermissions.viewer).toEqual(["view:tools"]);
      expect(res.value.rollbackSnapshot.viewer).toEqual(["view:tools", "view:dashboard"]);
    });
  });

  describe("failure paths and validation guards", () => {
    it("rejects unknown or invalid role definitions with invalid_role_definition", () => {
      const invalidRoles = {
        ...basePermissions,
        superadmin: ["admin:recovery"] // invalid role
      } as unknown as Record<Role, Permission[]>;

      const res = PermissionDiffEngine.generateDiffReport(basePermissions, invalidRoles, {
        caller: maintainerContext
      });

      expect(res.ok).toBe(false);
      if (!res.ok) expect(res.code).toBe("invalid_role_definition");
    });

    it("rejects unknown permissions with invalid_permission", () => {
      const invalidPerms = {
        ...basePermissions,
        viewer: ["view:tools", "root:destroy_all" as Permission]
      };

      const res = PermissionDiffEngine.generateDiffReport(basePermissions, invalidPerms, {
        caller: maintainerContext
      });

      expect(res.ok).toBe(false);
      if (!res.ok) expect(res.code).toBe("invalid_permission");
    });

    it("rejects empty permission mapping with empty_permissions", () => {
      const empty = {} as Record<Role, Permission[]>;

      const res = PermissionDiffEngine.generateDiffReport(basePermissions, empty, {
        caller: maintainerContext
      });

      expect(res.ok).toBe(false);
      if (!res.ok) expect(res.code).toBe("empty_permissions");
    });
  });

  describe("authorization path", () => {
    it("denies preview generation for non-maintainer callers with unauthorized", () => {
      const res = PermissionDiffEngine.generateDiffReport(basePermissions, basePermissions, {
        caller: viewerContext
      });

      expect(res.ok).toBe(false);
      if (!res.ok) expect(res.code).toBe("unauthorized");
    });

    it("permits preview generation for maintainer caller", () => {
      const res = PermissionDiffEngine.generateDiffReport(basePermissions, basePermissions, {
        caller: maintainerContext
      });

      expect(res.ok).toBe(true);
    });
  });

  describe("risk detection, privilege escalation, and lockout edge cases", () => {
    it("blocks critical privilege escalation to non-maintainer role by default", () => {
      const criticalEscalation: Record<Role, Permission[]> = {
        ...basePermissions,
        viewer: ["view:tools", "view:dashboard", "admin:recovery"]
      };

      const reportRes = PermissionDiffEngine.generateDiffReport(basePermissions, criticalEscalation, {
        caller: maintainerContext
      });
      expect(reportRes.ok).toBe(true);
      if (!reportRes.ok) return;

      expect(reportRes.value.overallRiskLevel).toBe("critical");
      expect(reportRes.value.recommendedAction).toBe("block");
      expect(reportRes.value.executionPlan.allowApply).toBe(false);

      // Attempting to apply directly fails with critical_escalation_blocked
      const applyRes = PermissionDiffEngine.applyRolePolicyChange(basePermissions, criticalEscalation, {
        caller: maintainerContext
      });
      expect(applyRes.ok).toBe(false);
      if (!applyRes.ok) expect(applyRes.code).toBe("critical_escalation_blocked");
    });

    it("detects administrator lockout risk when maintainer permissions are stripped", () => {
      const lockoutProposed: Record<Role, Permission[]> = {
        ...basePermissions,
        maintainer: [] // emptied maintainer
      };

      const res = PermissionDiffEngine.generateDiffReport(basePermissions, lockoutProposed, {
        caller: maintainerContext
      });

      expect(res.ok).toBe(true);
      if (!res.ok) return;

      expect(res.value.overallRiskLevel).toBe("critical");
      expect(res.value.warnings.some((w) => w.includes("LOCKOUT RISK"))).toBe(true);
      expect(res.value.executionPlan.allowApply).toBe(false);
    });

    it("allows applying critical escalations only when explicitly override allowed", () => {
      const criticalEscalation: Record<Role, Permission[]> = {
        ...basePermissions,
        viewer: ["view:tools", "view:dashboard", "admin:recovery"]
      };

      const res = PermissionDiffEngine.applyRolePolicyChange(basePermissions, criticalEscalation, {
        caller: maintainerContext,
        allowCriticalEscalations: true
      });

      expect(res.ok).toBe(true);
    });
  });

  describe("retry path", () => {
    it("retries diff report on transient failures up to maxRetries", () => {
      let attempts = 0;
      const fn = () => {
        attempts += 1;
        if (attempts < 3) {
          return { ok: false as const, code: "empty_permissions" as const };
        }
        return PermissionDiffEngine.generateDiffReport(basePermissions, basePermissions, {
          caller: maintainerContext
        });
      };

      const res = PermissionDiffEngine.retryDiffReport(fn, 3);
      expect(res.ok).toBe(true);
      expect(attempts).toBe(3);
    });
  });
});
