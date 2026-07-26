import assert from "node:assert/strict";
import test from "node:test";
import type { Project, ProjectRole } from "../src/lib/domain";
import { authorizeProject, canAccess, type ProjectAction } from "../src/lib/mvp-store";

function project(role: ProjectRole): Project {
  return {
    id: "project-security-test",
    name: "安全测试项目",
    city: "上海市",
    status: "DRAFT",
    ownerEmail: "owner@example.com",
    memberEmails: ["member@example.com"],
    memberRoles: { "member@example.com": role },
    venue: {
      address: "测试地址",
      district: "浦东新区",
      areaSqm: 1000,
      clearHeightM: 9,
      certificateUsage: "测试",
      intendedUsage: "匹克球馆",
      monthlyRent: null,
      leaseMonths: null,
      plannedCourts: 4,
    },
    checklist: [],
    createdAt: "2026-01-01T00:00:00.000Z",
    updatedAt: "2026-01-01T00:00:00.000Z",
  };
}

const privilegedActions: ProjectAction[] = [
  "EDIT_PROJECT",
  "UPDATE_CHECKLIST",
  "REVIEW_AI",
  "GENERATE_REPORT",
  "MANAGE_RISKS",
  "MANAGE_TASKS",
  "EDIT_OPERATIONS",
  "DECIDE_STAGE",
  "MANAGE_EXPERT_ASSIGNMENTS",
  "MANAGE_MEMBERS",
];

test("ordinary project members can view but cannot perform privileged writes", () => {
  const target = project("MEMBER");
  assert.equal(canAccess(target, "MEMBER@example.com", "MEMBER"), true);
  for (const action of privilegedActions) {
    assert.equal(authorizeProject(target, "member@example.com", "MEMBER", action), false, action);
  }
});

test("project managers and administrators can perform all privileged writes", () => {
  const target = project("PROJECT_MANAGER");
  for (const action of privilegedActions) {
    assert.equal(authorizeProject(target, "member@example.com", "MEMBER", action), true, action);
    assert.equal(authorizeProject(target, "admin@example.com", "ADMIN", action), true, action);
  }
});

test("specialized roles only receive their explicit permissions", () => {
  const reviewer = project("REVIEWER");
  assert.equal(authorizeProject(reviewer, "member@example.com", "MEMBER", "UPDATE_CHECKLIST"), true);
  assert.equal(authorizeProject(reviewer, "member@example.com", "MEMBER", "REVIEW_AI"), true);
  assert.equal(authorizeProject(reviewer, "member@example.com", "MEMBER", "GENERATE_REPORT"), false);
  assert.equal(authorizeProject(reviewer, "member@example.com", "MEMBER", "DECIDE_STAGE"), false);

  const decisionMaker = project("DECISION_MAKER");
  assert.equal(authorizeProject(decisionMaker, "member@example.com", "MEMBER", "GENERATE_REPORT"), true);
  assert.equal(authorizeProject(decisionMaker, "member@example.com", "MEMBER", "DECIDE_STAGE"), true);
  assert.equal(authorizeProject(decisionMaker, "member@example.com", "MEMBER", "EDIT_PROJECT"), false);
});
