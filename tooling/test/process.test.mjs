import assert from "node:assert/strict";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { CommandError, runCommand } from "../lib/process.mjs";

const fixture = (name) => fileURLToPath(new URL(`../testdata/${name}`, import.meta.url));

test("runCommand returns captured output", async () => {
  const result = await runCommand(process.execPath, ["--version"], { capture: true });
  assert.match(result.stdout, /^v\d+/);
});

test("runCommand reports a failing subprocess", async () => {
  await assert.rejects(
    runCommand(process.execPath, [fixture("failing-command.mjs")], { capture: true }),
    (error) => error instanceof CommandError && error.code === 7 && error.timedOut === false,
  );
});

test("runCommand interrupts a timed-out subprocess", async () => {
  await assert.rejects(
    runCommand(process.execPath, [fixture("slow-command.mjs")], {
      capture: true,
      timeoutMs: 50,
    }),
    (error) => error instanceof CommandError && error.timedOut === true,
  );
});
