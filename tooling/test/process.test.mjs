import assert from "node:assert/strict";
import { access, mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
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
    runCommand(process.execPath, ["-e", "process.stdout.write('safe stdout\\n'); process.stderr.write('safe stderr\\n'); process.exit(7)"], { capture: true }),
    (error) => error instanceof CommandError && error.code === 7 && error.timedOut === false &&
      error.stdout === "safe stdout\n" && error.stderr === "safe stderr\n",
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

test("a stubborn process tree is killed before it can mutate after timeout", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "vegastack-process-"));
  const marker = path.join(root, "late-mutation.txt");
  const started = performance.now();

  await assert.rejects(
    runCommand(process.execPath, [fixture("stubborn-tree.mjs"), marker], {
      capture: true,
      terminationGraceMs: 50,
      timeoutMs: 50,
    }),
    (error) => error instanceof CommandError && error.timedOut === true,
  );
  assert.ok(performance.now() - started < 500, "timeout must remain bounded");
  await new Promise((resolve) => setTimeout(resolve, 400));
  await assert.rejects(access(marker), { code: "ENOENT" });
});
