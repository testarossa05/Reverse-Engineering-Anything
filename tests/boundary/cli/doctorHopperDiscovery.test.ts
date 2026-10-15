import { access, chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { delimiter, join } from "node:path";

import { expect } from "vitest";

import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { cliTest } from "../../support/cli/cliFixture.js";

cliTest.skipIf(!["darwin", "linux"].includes(process.platform))(
  "retains a configured Hopper path in host diagnostics without launching it",
  async ({ cli }) => {
    const home = await createTestTempDirectory("rea-doctor-hopper-home-");
    const launcher = `${home}/bin/../bin/hopper`;
    const launchMarker = join(home, "hopper-was-launched");
    await mkdir(join(home, "bin"), { recursive: true });
    await writeFile(
      launcher,
      '#!/bin/sh\nprintf launched > "$REA_HOPPER_TEST_MARKER"\nexit 99\n',
    );
    await chmod(launcher, 0o700);
    const loaderMarker = join(home, "loader-checked-launcher");
    if (process.platform === "linux") {
      // A shell fixture needs controlled loader diagnostics on Linux. This
      // checks discovery and path preservation, not actual Hopper compatibility.
      const loader = join(home, "bin", "ldd");
      await writeFile(
        loader,
        [
          "#!/bin/sh",
          'test "$#" -eq 1 || exit 87',
          'test "$1" = "$HOPPER_LAUNCHER_PATH" || exit 88',
          'printf "%s" "$1" > "$REA_HOPPER_LDD_TEST_MARKER"',
          'printf "%s\\n" "libc.so.6 => /fixture/libc.so.6 (0x1)"',
          "",
        ].join("\n"),
      );
      await chmod(loader, 0o700);
    }

    const result = await cli.run({
      arguments: ["doctor", "--provider", "hopper", "--json"],
      cwd: home,
      environment: {
        ...(process.platform === "linux"
          ? {
              PATH: [join(home, "bin"), process.env.PATH ?? ""].join(delimiter),
              REA_HOPPER_LDD_TEST_MARKER: loaderMarker,
              NODE_OPTIONS: `--import=${new URL("../../fixtures/hopperRejectionFeed.mjs", import.meta.url).href}`,
            }
          : {}),
        HOME: home,
        USERPROFILE: home,
        HOPPER_LAUNCHER_PATH: launcher,
        REA_HOPPER_TEST_MARKER: launchMarker,
        GHIDRA_INSTALL_DIR: join(home, "missing-ghidra"),
      },
      timeoutMs: 20_000,
    });

    const hopperReady = process.platform === "darwin";
    expect(result.signal).toBeNull();
    expect(result.exitCode).toBe(hopperReady ? 0 : 1);
    expect(result.json).toMatchObject({
      healthy: hopperReady,
      environment_healthy: false,
      hopperPath: launcher,
      checks: expect.arrayContaining([
        expect.objectContaining({
          name: "hopper",
          ok: true,
          detail: launcher,
          classification: "healthy",
        }),
        ...(process.platform === "linux"
          ? [
              expect.objectContaining({
                name: "hopper-version",
                ok: false,
                detail: launcher,
                classification: "config_drift",
                remediation: expect.stringContaining("HOPPER_LAUNCHER_PATH"),
              }),
            ]
          : []),
      ]),
    });
    await expect(access(launchMarker)).rejects.toMatchObject({
      code: "ENOENT",
    });
    if (process.platform === "linux")
      expect(await readFile(loaderMarker, "utf8")).toBe(launcher);
  },
);
