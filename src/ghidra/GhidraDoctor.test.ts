import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { runDoctor, type DoctorHost } from "../application/Doctor.js";
import { createDoctorHostFixture } from "../application/Doctor.fixture.js";
import { providerRegistrationEnvironment } from "../application/SetupRegistrationEnvironment.js";
import { WINDOWS_NATIVE_AUTHORITY_UNAVAILABLE_REASON } from "../process/WindowsAuthority.js";
import * as nativeLoader from "../windows/WindowsNativeLoader.js";
import {
  inspectGhidraInstallation,
  type GhidraInstallationHost,
  type GhidraInstallationInspection,
} from "./GhidraInstallation.js";
import { projectGhidraDoctorInspection } from "./GhidraDoctor.js";

const INSTALL = "/opt/ghidra_12.1.4_PUBLIC";
const installationHost = (
  overrides: Partial<GhidraInstallationHost> = {},
  platform: NodeJS.Platform = "linux",
): GhidraInstallationHost => ({
  readText: () => "application.version=12.1.4\napplication.java.min=21\n",
  executable: () => true,
  probeJava: () => ({
    osArch: "amd64",
    osName: platform === "win32" ? "Windows 11" : "Linux",
    version: "21.0.11",
    major: 21,
    home: "/usr/lib/jvm/jdk-21",
    bits: 64,
    runtime: "jdk",
  }),
  ...overrides,
});

const inspection = (
  options: {
    readonly installDir?: string;
    readonly architecture?: NodeJS.Architecture;
    readonly platform?: NodeJS.Platform;
  } = { installDir: INSTALL },
  overrides: Partial<GhidraInstallationHost> = {},
): GhidraInstallationInspection =>
  inspectGhidraInstallation(
    {
      environment: {},
      platform: options.platform ?? "linux",
      architecture: options.architecture ?? "x64",
      ...(options.installDir === undefined
        ? {}
        : { installDir: options.installDir }),
    },
    installationHost(overrides, options.platform ?? "linux"),
  );

const doctorHost = (
  ghidra: GhidraInstallationInspection,
  hopperAvailable = false,
): DoctorHost =>
  createDoctorHostFixture({
    platform: "linux",
    architecture: "x64",
    macosVersion: () => Promise.resolve(undefined),
    linuxDistribution: () =>
      Promise.resolve({
        id: "ubuntu",
        versionId: "24.04",
        packageFamily: "deb",
        hopperSetupSupported: true,
      }),
    validTarget: () => Promise.resolve(true),
    executable: (path) =>
      Promise.resolve(hopperAvailable && path.includes("Hopper")),
    linuxDemoRuntimeCheck: () =>
      Promise.resolve({
        name: "hopper-demo-runtime",
        ok: true,
        classification: "healthy",
      }),
    brewHopperPath: () => Promise.resolve(undefined),
    manualHopperPaths: () => Promise.resolve([]),
    providerInspections: () =>
      Promise.resolve([projectGhidraDoctorInspection(ghidra)]),
  });

describe("Ghidra doctor integration", () => {
  it("accepts a valid BYO Ghidra engine when Hopper is absent", async () => {
    const result = await runDoctor(undefined, doctorHost(inspection()));

    expect(result.healthy).toBe(true);
    expect(result.hopperPath).toBeUndefined();
    expect(result.providerInspections?.[0]).toMatchObject({
      id: "ghidra",
      available: true,
      providerVersion: "12.1.4",
      registrationEnvironment: {
        GHIDRA_INSTALL_DIR: INSTALL,
        JAVA_HOME: "/usr/lib/jvm/jdk-21",
      },
    });
    expect(
      result.checks.find(({ name }) => name === "ghidra-java"),
    ).toMatchObject({
      ok: true,
      detail: expect.stringContaining("21.0.11"),
    });
  });

  it.each([
    [
      "bad installation",
      inspection({ installDir: INSTALL }, { readText: () => undefined }),
      "ghidra-installation",
    ],
    [
      "wrong version",
      inspection(
        { installDir: INSTALL },
        {
          readText: () => "application.version=11.4\napplication.java.min=21\n",
        },
      ),
      "ghidra-version",
    ],
    [
      "missing analyzeHeadless",
      inspection({ installDir: INSTALL }, { executable: () => false }),
      "ghidra-headless",
    ],
    [
      "wrong Java",
      inspection(
        { installDir: INSTALL },
        {
          probeJava: () => ({
            osArch: "amd64",
            osName: "Linux",
            version: "17.0.12",
            major: 17,
            home: "/usr/lib/jvm/jdk-17",
            bits: 64,
            runtime: "jdk",
          }),
        },
      ),
      "ghidra-java",
    ],
    [
      "missing Java minimum",
      inspection(
        { installDir: INSTALL },
        { readText: () => "application.version=12.1.4\n" },
      ),
      "ghidra-java",
    ],
    [
      "unsupported architecture",
      inspection({ installDir: INSTALL, architecture: "arm" }),
      "ghidra-architecture",
    ],
  ] as const)("distinguishes %s", async (_label, ghidra, checkName) => {
    const result = await runDoctor(undefined, doctorHost(ghidra, true));

    expect(result.healthy).toBe(false);
    expect(result.checks.find(({ name }) => name === checkName)).toMatchObject({
      ok: false,
      remediation: expect.any(String),
    });
  });

  it("treats unconfigured Ghidra as optional when Hopper is healthy", async () => {
    const result = await runDoctor(undefined, doctorHost(inspection({}), true));

    expect(result.healthy).toBe(true);
    expect(result.checks.find(({ name }) => name === "ghidra")).toMatchObject({
      ok: false,
      classification: "missing_analysis_engine",
    });
  });
});

describe("Windows Ghidra doctor authority", () => {
  beforeEach(() => {
    vi.spyOn(nativeLoader, "systemWindowsNativeAuthority").mockReturnValue({
      available: false,
      failureStage: "artifact",
      reason: WINDOWS_NATIVE_AUTHORITY_UNAVAILABLE_REASON,
    });
  });
  afterEach(() => vi.restoreAllMocks());
  it("distinguishes a valid Windows installation from unavailable native authority", async () => {
    const ghidra = inspection({
      installDir: "C:\\tools\\ghidra_12.1.4_PUBLIC",
      platform: "win32",
    });
    const result = await runDoctor(undefined, {
      ...doctorHost(ghidra),
      platform: "win32",
      architecture: "x64",
      linuxDistribution: () => Promise.resolve(undefined),
    });

    expect(result.healthy).toBe(false);
    expect(result.providerInspections?.[0]).toMatchObject({
      available: false,
      providerVersion: "12.1.4",
      registrationEnvironment: {
        GHIDRA_INSTALL_DIR: "C:\\tools\\ghidra_12.1.4_PUBLIC",
      },
    });
    expect(
      providerRegistrationEnvironment(result.providerInspections ?? []),
    ).toMatchObject({
      GHIDRA_INSTALL_DIR: "C:\\tools\\ghidra_12.1.4_PUBLIC",
    });
    expect(result.checks.find(({ name }) => name === "host")).toMatchObject({
      ok: true,
      detail: "win32 x64",
    });
    expect(result.checks.find(({ name }) => name === "ghidra")).toMatchObject({
      ok: true,
    });
    expect(
      result.checks.find(({ name }) => name === "ghidra-java"),
    ).toMatchObject({ ok: true });
    expect(
      result.checks.find(({ name }) => name === "ghidra-native_authority"),
    ).toMatchObject({
      ok: false,
      classification: "missing_dependency",
      detail: WINDOWS_NATIVE_AUTHORITY_UNAVAILABLE_REASON,
      remediation: expect.stringContaining("matching Windows x64 REA package"),
    });
  });

  it("fails provider-scoped Windows readiness without blaming installation", async () => {
    const ghidra = inspection({
      installDir: "C:\\tools\\ghidra_12.1.4_PUBLIC",
      platform: "win32",
    });
    const result = await runDoctor(
      undefined,
      {
        ...doctorHost(ghidra),
        platform: "win32",
        linuxDistribution: () => Promise.resolve(undefined),
      },
      { providers: ["ghidra"] },
    );
    expect(result.healthy).toBe(false);
    expect(result.scope_checks).toContainEqual(
      expect.objectContaining({
        name: "ghidra-native_authority",
        classification: "missing_dependency",
        detail: WINDOWS_NATIVE_AUTHORITY_UNAVAILABLE_REASON,
      }),
    );
  });
});

describe("Windows native doctor failure diagnostics", () => {
  beforeEach(() => {
    vi.spyOn(nativeLoader, "systemWindowsNativeAuthority").mockReturnValue({
      available: false,
      failureStage: "artifact",
      reason: WINDOWS_NATIVE_AUTHORITY_UNAVAILABLE_REASON,
    });
  });
  afterEach(() => vi.restoreAllMocks());

  it.each([
    ["host", "unsupported_host", "unsupported_host", "Windows x64 host"],
    [
      "artifact",
      "runtime_missing",
      "missing_dependency",
      "native/windows/README.md",
    ],
    [
      "self-test",
      "runtime_unavailable",
      "runtime_failure",
      "preserved native self-test error",
    ],
    [
      "inspection",
      "runtime_unavailable",
      "runtime_failure",
      "every required security control",
    ],
  ] as const)(
    "projects %s failure without blaming Ghidra",
    async (failureStage, code, classification, remediation) => {
      const reason =
        "Windows native failure: remove_owned_directory: directory is not empty (145)";
      const load = vi.mocked(nativeLoader.systemWindowsNativeAuthority);
      load.mockReturnValue({ available: false, failureStage, reason });
      const result = await runDoctor(
        undefined,
        {
          ...doctorHost(inspection({ installDir: INSTALL, platform: "win32" })),
          platform: "win32",
          linuxDistribution: () => Promise.resolve(undefined),
        },
        { providers: ["ghidra"] },
      );
      expect(load).toHaveBeenCalledTimes(1);
      expect(result.healthy).toBe(false);
      expect(result.providerInspections?.[0]).toMatchObject({
        available: false,
        registrationEnvironment: { GHIDRA_INSTALL_DIR: INSTALL },
        checks: expect.arrayContaining([
          expect.objectContaining({
            name: "native_authority",
            ok: false,
            code,
            detail: reason,
          }),
        ]),
      });
      expect(result.scope_checks).toContainEqual(
        expect.objectContaining({
          name: "ghidra-native_authority",
          classification,
          detail: reason,
          remediation: expect.stringContaining(remediation),
        }),
      );
    },
  );

  it("keeps one failure observation even when the next query would differ", () => {
    const load = vi.mocked(nativeLoader.systemWindowsNativeAuthority);
    load.mockReturnValueOnce({
      available: false,
      failureStage: "self-test",
      retryable: true,
      reason: "cleanup failed (145)",
    });
    const ghidra = inspection({ installDir: INSTALL, platform: "win32" });
    const failed = projectGhidraDoctorInspection(ghidra);
    expect(load).toHaveBeenCalledTimes(1);
    expect(failed.checks).toContainEqual(
      expect.objectContaining({
        name: "native_authority",
        ok: false,
        code: "runtime_unavailable",
        detail: "cleanup failed (145)",
      }),
    );
    const later = projectGhidraDoctorInspection(ghidra);
    expect(load).toHaveBeenCalledTimes(2);
    expect(later.checks).toContainEqual(
      expect.objectContaining({
        name: "native_authority",
        code: "runtime_missing",
        detail: WINDOWS_NATIVE_AUTHORITY_UNAVAILABLE_REASON,
      }),
    );
  });

  it("keeps missing Windows Java actionable as a dependency failure", () => {
    const projected = projectGhidraDoctorInspection(
      inspection(
        {
          installDir: "C:\\tools\\ghidra_12.1.4_PUBLIC",
          platform: "win32",
        },
        { probeJava: () => undefined },
      ),
    );
    expect(projected.available).toBe(false);
    expect(projected.checks).toContainEqual(
      expect.objectContaining({
        name: "java",
        ok: false,
        classification: "missing_dependency",
        remediation: expect.any(String),
      }),
    );
  });
});
