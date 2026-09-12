import { fullCheckPlan, runCheckPlan } from "./lib/check-plan.mjs";

try {
  await runCheckPlan(fullCheckPlan());

  process.stdout.write(
    `${JSON.stringify({ schemaVersion: 1, check: "foundation", status: "pass" })}\n`,
  );
} catch (error) {
  process.stderr.write(`foundation check failed: ${error.message}\n`);
  process.exitCode = 1;
}
