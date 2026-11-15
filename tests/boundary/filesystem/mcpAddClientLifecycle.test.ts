import { chmod, mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { afterEach, beforeEach, expect, it, vi } from "vitest";

import { parseClientConfiguration } from "../../../src/application/ClientConfigurationDocument.js";
import { currentClientRegistrationCommand } from "../../../src/application/ClientRegistrationIdentity.js";
import { readClientRegistrationStatuses } from "../../../src/application/ClientRegistrationStatus.js";
import { registerMcpClients } from "../../../src/application/McpClientRegistration.js";
import { resolveMcpRegistrationClients } from "../../../src/application/McpRegistrationCatalog.js";
import {
  configureClientConfiguration,
  inspectClientConfiguration,
} from "../../../src/application/SetupClientConfiguration.js";
import { supportedClients } from "../../../src/application/SupportedClients.js";
import { detectClients } from "../../../src/application/SetupHost.js";
import {
  runUninstall,
  systemUninstallHost,
} from "../../../src/application/Uninstall.js";
import { existingMaintenanceScope } from "../../../src/application/UpdateMaintenance.js";
import { ArtifactResourceScope } from "../../../src/artifacts/ArtifactResourceScope.js";
import { clearClientLocationEnvironment } from "../../fixtures/clientEnvironment.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

const platform = process.platform;
const command = currentClientRegistrationCommand({ platform });

beforeEach(clearClientLocationEnvironment);
afterEach(() => vi.unstubAllEnvs());

// Each client REA registers through `rea mcp add` is one client-table row, so
// doctor, update and uninstall see what mcp add wrote (#7181).
it.each([
  { agent: "cline", client: "cline_vscode" },
  { agent: "kiro-cli", client: "kiro" },
  { agent: "mastracode", client: "mastracode" },
  { agent: "zed", client: "zed" },
  { agent: "amp", client: "amp" },
  { agent: "mcporter", client: "mcporter" },
  { agent: "fx", client: "fx" },
  { agent: "junie", client: "junie" },
])(
  "inspects, refreshes and removes the $agent registration that mcp add wrote as $client",
  async ({ agent, client }) => {
    const home = await createTestTempDirectory(`rea-mcp-add-${client}-`);
    const environment = {};
    const resources = new ArtifactResourceScope();
    const selected = await resolveMcpRegistrationClients(
      { agents: [agent], global: true, cwd: home, home, platform, environment },
      resources,
    );
    if (!selected.ok) throw selected.error;
    const row = supportedClients(home, platform, environment).find(
      ({ name }) => name === client,
    );
    if (row === undefined) throw new Error(`${client} has no table row`);
    expect(selected.value.map(({ configPath }) => configPath)).toEqual([
      row.configPath,
    ]);

    // An older, still REA-owned launcher: the package runner form that
    // current setup migrates to the selected installation.
    const legacy = { command: "npx", args: ["-y", "rea-agents@1.0.0", "mcp"] };
    const [outcome] = await registerMcpClients(
      selected.value,
      legacy,
      undefined,
      resources,
    );
    expect(outcome).toMatchObject({
      status: "completed",
      result: { ok: true, value: { status: "configured" } },
    });
    const status = async () =>
      (
        await readClientRegistrationStatuses(home, command[1], {
          platform,
          environment,
        })
      ).find((entry) => entry.client === client);

    // Doctor reads the registration from the same row.
    expect(await status()).toMatchObject({
      config_path: row.configPath,
      command: [legacy.command, ...legacy.args],
      command_identity: "owned",
      state: "stale",
    });
    // Update selects it, and setup refreshes it to the current launcher.
    await expect(
      existingMaintenanceScope(home, command[1] ?? "", environment),
    ).resolves.toMatchObject({ clients: [client] });
    await expect(
      inspectClientConfiguration(row, {}, command),
    ).resolves.toMatchObject({ status: "update" });
    await expect(
      configureClientConfiguration(row, {}, command),
    ).resolves.toMatchObject({ status: "configured" });
    expect(await status()).toMatchObject({
      command: [...command],
      command_identity: "owned",
    });

    // Uninstall removes only REA's row and keeps the file.
    const uninstall = await runUninstall(
      false,
      systemUninstallHost(home, undefined, environment, platform),
    );
    expect(uninstall.items).toContainEqual(
      expect.objectContaining({ name: client, status: "removed" }),
    );
    const remaining = parseClientConfiguration(
      await readFile(row.configPath, "utf8"),
      row.format,
    );
    expect(remaining.servers).not.toHaveProperty("rea");
    if (row.privateProfile === true && platform !== "win32")
      expect((await stat(row.configPath)).mode & 0o777).toBe(0o600);
  },
);

it("keeps MCPorter out of setup detection and doctor until REA registers it", async () => {
  const home = await createTestTempDirectory("rea-mcporter-applicability-");
  const environment = {};
  const row = supportedClients(home, platform, environment).find(
    ({ name }) => name === "mcporter",
  );
  if (row === undefined) throw new Error("mcporter has no table row");
  await mkdir(join(home, ".mcporter"), { recursive: true });
  await writeFile(
    row.configPath,
    `${JSON.stringify({ mcpServers: { peer: { command: "peer" } } })}\n`,
  );
  expect(
    (await detectClients(home, platform, environment)).map(({ name }) => name),
  ).not.toContain("mcporter");
  const statuses = await readClientRegistrationStatuses(home, command[1], {
    platform,
    environment,
  });
  expect(statuses.map(({ client }) => client)).not.toContain("mcporter");
  // An explicit selection still reports the missing registration.
  const selected = await readClientRegistrationStatuses(home, command[1], {
    platform,
    environment,
    selectedClientIds: ["mcporter"],
  });
  expect(selected.find(({ client }) => client === "mcporter")).toMatchObject({
    state: "missing",
  });
});

it.skipIf(platform === "win32")(
  "setup publishes fx's profile privately and repairs its modes",
  async () => {
    const home = await createTestTempDirectory("rea-fx-private-");
    const row = supportedClients(home, platform, {}).find(
      ({ name }) => name === "fx",
    );
    if (row === undefined) throw new Error("fx has no table row");
    const modes = async () => ({
      directory: (await stat(dirname(row.configPath))).mode & 0o777,
      file: (await stat(row.configPath)).mode & 0o777,
    });
    await expect(
      configureClientConfiguration(row, {}, command),
    ).resolves.toMatchObject({ status: "configured" });
    expect(await modes()).toEqual({ directory: 0o700, file: 0o600 });
    await expect(inspectClientConfiguration(row, {}, command)).resolves.toEqual(
      { status: "already_current" },
    );

    // A current row in a readable profile still needs its modes restored.
    await chmod(row.configPath, 0o644);
    await chmod(dirname(row.configPath), 0o755);
    await expect(
      inspectClientConfiguration(row, {}, command),
    ).resolves.toMatchObject({ status: "update" });
    await expect(
      configureClientConfiguration(row, {}, command),
    ).resolves.toMatchObject({ status: "configured" });
    expect(await modes()).toEqual({ directory: 0o700, file: 0o600 });
  },
);

it("reports a Junie registration Junie would not load in doctor and setup", async () => {
  const home = await createTestTempDirectory("rea-junie-policy-");
  const environment = { JUNIE_MCP_DEFAULT_LOCATIONS: "false" };
  const row = supportedClients(home, platform, environment).find(
    ({ name }) => name === "junie",
  );
  if (row === undefined) throw new Error("junie has no table row");
  await mkdir(dirname(row.configPath), { recursive: true });
  await writeFile(
    row.configPath,
    `${JSON.stringify({ mcpServers: { rea: { command: command[0], args: command.slice(1) } } })}\n`,
  );
  const status = (
    await readClientRegistrationStatuses(home, command[1], {
      platform,
      environment,
    })
  ).find(({ client }) => client === "junie");
  expect(status).toMatchObject({
    state: "stale",
    remediation: expect.stringContaining("JUNIE_MCP_DEFAULT_LOCATIONS"),
  });
  await expect(
    inspectClientConfiguration(row, {}, command),
  ).resolves.toMatchObject({ status: "invalid" });
});
