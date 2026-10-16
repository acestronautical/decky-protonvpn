import {
  ConfirmModal,
  DialogButton,
  DropdownItem,
  Focusable,
  PanelSection,
  PanelSectionRow,
  TextField,
  Tabs,
  ToggleField,
  showModal,
  staticClasses,
} from "@decky/ui";
import { callable, definePlugin, toaster } from "@decky/api";
import { useEffect, useRef, useState, useSyncExternalStore } from "react";
import { FaBolt, FaDownload, FaExchangeAlt, FaPowerOff, FaSignOutAlt, FaSlidersH, FaSyncAlt, FaUser } from "react-icons/fa";
import { cachedUsername, encodeSignIn, encryptSignIn, rememberUsername } from "./signin";
import protonIcon from "../protonvpn-dark.png";
import countryNames from "../py_modules/protonvpn/countries.json";

type ProtonCountry = {
  code: string;
  name: string;
};

type InstallationStatus = {
  state: "idle" | "running" | "succeeded" | "failed" | "blocked" | "unknown";
  stage?: string;
  error?: string;
};

type ProtonStatus = {
  installation?: InstallationStatus;
  installed: boolean | null;
  signed_in: boolean | null;
  account_name?: string | null;
  connected: boolean | null;
  tunnel_active?: boolean | null;
  server?: string;
  protocol?: string;
  error?: string;
  diagnostics?: Record<string, string>;
  can_start_keyring?: boolean;
  kill_switch?: boolean | null;
  settings?: Record<string, string | null>;
  settings_error?: string;
  requires_upgrade?: string[];
  requires_reconnect?: string[];
  notice?: string;
};

type ConnectionStatus = Pick<ProtonStatus, "connected" | "tunnel_active" | "server" | "protocol" | "error">;

const countries: ProtonCountry[] = Object.entries(countryNames)
  .map(([code, name]) => ({ code, name }))
  .sort((first, second) => first.name.localeCompare(second.name));

type SignInSession = {
  session_id: string;
  public_key: string;
};

type SignInError = { error: string };

const getStatus = callable<[], ProtonStatus>("get_status");
const getConnectionStatus = callable<[], ConnectionStatus>("get_connection_status");
const startKeyring = callable<[], ProtonStatus>("start_keyring");
const beginSignIn = callable<[], SignInSession | SignInError>("begin_signin");
const cancelSignIn = callable<[sessionId: string], void>("cancel_signin");
const completeSignIn = callable<
  [sessionId: string, ciphertext: string],
  ProtonStatus | SignInError
>("complete_signin");
const connectCountry = callable<[countryCode: string], ProtonStatus>(
  "connect_country",
);
const disconnect = callable<[], ProtonStatus>("disconnect");
const quickConnect = callable<[], ProtonStatus>("quick_connect");
const signOut = callable<[], ProtonStatus>("signout");
const installProton = callable<[], InstallationStatus>("install_proton");
const getInstallationStatus = callable<[], InstallationStatus>("get_installation_status");
const setKillSwitch = callable<[enabled: boolean], ProtonStatus>("set_kill_switch");
const setFeature = callable<[name: string, value: string], ProtonStatus>("set_feature");

let detailsRequest: Promise<ProtonStatus> | undefined;
let mutationRequest: Promise<unknown> | undefined;
const mutationListeners = new Set<() => void>();
let installationState: InstallationStatus = { state: "idle" };

function getInstallationState() {
  return installationState;
}

async function waitForInstallation(job: InstallationStatus) {
  installationState = job;
  for (const listener of mutationListeners) listener();
  while (job.state === "running") {
    await new Promise(resolve => setTimeout(resolve, 1000));
    try {
      job = await getInstallationStatus();
    } catch {
      installationState = { state: "unknown" };
      for (const listener of mutationListeners) listener();
      throw new Error("Installation status is unavailable; refresh Account before retrying");
    }
    installationState = job;
    for (const listener of mutationListeners) listener();
  }
  return job;
}

function subscribeMutation(listener: () => void) {
  mutationListeners.add(listener);
  return () => { mutationListeners.delete(listener); };
}

function mutationPending() {
  return mutationRequest !== undefined;
}

function runMutation<Result>(action: () => Promise<Result>): Promise<Result> {
  if (mutationRequest) throw new Error("A Proton VPN operation is already in progress");
  const precedingRead = detailsRequest;
  const request = Promise.resolve().then(async () => {
    if (precedingRead) await precedingRead.catch(() => {});
    return action();
  }).finally(() => {
    mutationRequest = undefined;
    for (const listener of mutationListeners) listener();
  });
  mutationRequest = request;
  for (const listener of mutationListeners) listener();
  return request;
}

function readDetails() {
  if (!detailsRequest) {
    const precedingMutation = mutationRequest;
    detailsRequest = (async () => {
      if (precedingMutation) await precedingMutation.catch(() => {});
      let result = await getStatus();
      if (result.installation) {
        const job = await waitForInstallation(result.installation);
        if (result.installation.state === "running") result = await getStatus();
        if (job.error && result.installed !== true) result = { ...result, error: result.error ?? job.error };
      }
      return result;
    })().finally(() => { detailsRequest = undefined; });
  }
  return detailsRequest;
}

function ProtonIcon({ size = "1em" }: { size?: number | string }) {
  return (
    <img src={protonIcon} width={size} height={size} alt="Proton VPN" style={{ width: size, height: size, flexShrink: 0, objectFit: "contain" }} />
  );
}

const actionStyle = { width: "100%", minWidth: 0, minHeight: 44, padding: "10px 12px", borderRadius: 4, display: "flex", alignItems: "center", justifyContent: "center", gap: 8, whiteSpace: "normal" as const, overflowWrap: "anywhere" as const };

let pendingCountry = "";
let pendingNetshield: string | undefined;
let lastTab = "connection";
const countryListeners = new Set<() => void>();

function subscribeCountry(listener: () => void) {
  countryListeners.add(listener);
  return () => { countryListeners.delete(listener); };
}

function getSelectedCountry() {
  return pendingCountry;
}

function setSelectedCountry(country: string) {
  pendingCountry = country;
  for (const listener of countryListeners) listener();
}

function setSelectedNetshield(value: string | undefined) {
  pendingNetshield = value;
  for (const listener of countryListeners) listener();
}

function getSelectedNetshield() {
  return pendingNetshield;
}

function Content() {
  const [status, setStatus] = useState<ProtonStatus>();
  const [activeTab, setActiveTab] = useState(() => lastTab);
  const selectedCountry = useSyncExternalStore(subscribeCountry, getSelectedCountry);
  const selectedNetshield = useSyncExternalStore(subscribeCountry, getSelectedNetshield);
  const [username, setUsername] = useState(cachedUsername);
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const [error, setError] = useState<string>();
  const busy = useSyncExternalStore(subscribeMutation, mutationPending);
  const installation = useSyncExternalStore(subscribeMutation, getInstallationState);
  const [loadingSettings, setLoadingSettings] = useState(true);
  const [signingIn, setSigningIn] = useState(false);
  const [killSwitch, setKillSwitchValue] = useState<boolean | null>(null);
  const [refreshVersion, setRefreshVersion] = useState(0);
  const [showDiagnostics, setShowDiagnostics] = useState(false);
  const mounted = useRef(true);
  const signInRequest = useRef<{
    plaintext: Uint8Array;
    sessionId?: string;
  } | undefined>(undefined);

  const applyResult = (result: ConnectionStatus | ProtonStatus) => {
    setStatus((previous) => ({ installed: null, signed_in: null, ...previous, ...result, account_name: "installed" in result ? result.signed_in === true ? result.account_name ?? null : null : previous?.account_name, error: result.error, notice: "notice" in result ? result.notice : undefined }));
    setError(result.error ?? ("settings_error" in result ? result.settings_error : undefined));
    if ("kill_switch" in result) setKillSwitchValue(result.kill_switch ?? null);
  };

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      const request = signInRequest.current;
      request?.plaintext.fill(0);
      if (request?.sessionId) {
        void cancelSignIn(request.sessionId).catch(() => {});
      }
    };
  }, []);

  useEffect(() => {
    let current = true;
    setLoadingSettings(true);
    if (busy && activeTab !== "connection") return;
    const load = async () => {
      try {
        const result = await (activeTab === "connection" ? getConnectionStatus() : readDetails());
        if (current) applyResult(result);
        if (activeTab === "connection" && detailsRequest) {
          await detailsRequest.catch(() => {});
        }
      } catch (reason) {
        if (current) applyResult({ connected: null, tunnel_active: null, error: String(reason) });
      } finally {
        if (current) setLoadingSettings(false);
      }
    };
    void load();
    return () => { current = false; };
  }, [activeTab, refreshVersion, busy]);

  const runAction = async (action: () => Promise<ProtonStatus>, success: string) => {
    if (mutationPending() || signInRequest.current || loadingSettings) return;
    setError(undefined);
    try {
      const result = await runMutation(action);
      if (mounted.current) applyResult(result);
      if (!result.error && result.settings?.netshield === pendingNetshield) setSelectedNetshield(undefined);
      toaster.toast({ title: "Proton VPN", body: result.error ?? result.notice ?? success });
    } catch (reason) {
      const message = String(reason);
      if (mounted.current) setError(message);
      toaster.toast({ title: "Proton VPN", body: message });
    }
  };

  const performSignIn = async () => {
    setSigningIn(true);
    setError(undefined);
    try {
      if (!globalThis.crypto?.subtle) {
        throw new Error("Secure sign-in is unavailable here; use Desktop Mode sign-in");
      }
      const request: { plaintext: Uint8Array; sessionId?: string } = {
        plaintext: encodeSignIn({ username, password, totp }),
      };
      rememberUsername(username);
      signInRequest.current = request;
      setPassword("");
      setTotp("");
      const session = await beginSignIn();
      if ("error" in session) {
        throw new Error(session.error);
      }
      request.sessionId = session.session_id;
      if (!mounted.current) {
        return;
      }
      const ciphertext = await encryptSignIn(session.public_key, request.plaintext);
      if (!mounted.current) {
        return;
      }
      const result = await completeSignIn(session.session_id, ciphertext);
      if (!mounted.current) {
        return;
      }
      if (!("installed" in result)) {
        throw new Error(result.error);
      }
      applyResult(result);
      if (result.signed_in) {
        toaster.toast({ title: "Proton VPN", body: result.error ?? "Signed in" });
      }
    } catch (reason) {
      if (mounted.current) {
        const message = String(reason);
        setError(message);
        toaster.toast({ title: "Proton VPN", body: message });
      }
    } finally {
      const request = signInRequest.current;
      request?.plaintext.fill(0);
      if (request?.sessionId) {
        void cancelSignIn(request.sessionId).catch(() => {});
      }
      signInRequest.current = undefined;
      if (mounted.current) {
        setPassword("");
        setTotp("");
        setSigningIn(false);
      }
    }
  };

  const submitSignIn = async () => {
    if (signInRequest.current || mutationPending() || loadingSettings) return;
    await runMutation(performSignIn);
  };

  const selected = countries.find((country) => country.code === selectedCountry);
  const blocked = busy || signingIn || loadingSettings || installation.state === "running";
  const active = status?.tunnel_active === true || status?.connected === true;
  const canChangeKillSwitch = status?.connected === false && status?.tunnel_active === false;
  const connectionAction = selectedCountry ? () => connectCountry(selectedCountry) : quickConnect;
  const confirmSignOut = () => showModal(
    <ConfirmModal
      strTitle="Sign out of Proton VPN?"
      strDescription="This disconnects the VPN and signs out. Your saved username stays on this device."
      strOKButtonText="Sign out"
      strCancelButtonText="Cancel"
      bDestructiveWarning
      onOK={() => void runAction(signOut, "Signed out")}
    />,
  );
  const confirmInstall = () => showModal(
    <ConfirmModal
      strTitle="Install Proton VPN?"
      strDescription="Download Proton VPN and its required runtimes from Flathub for this user. The official user Flathub repository will be added if missing. This may use substantial disk space and take several minutes."
      strOKButtonText="Install"
      strCancelButtonText="Cancel"
      onOK={() => void runAction(async () => {
        const job = await waitForInstallation(await installProton());
        const result = await getStatus();
        return { ...result, error: job.error ?? result.error };
      }, "Proton VPN installed")}
    />,
  );
  const changeKillSwitch = (enabled: boolean) => {
    if (blocked || killSwitch === null || !canChangeKillSwitch) return;
    if (enabled) {
      void runAction(() => setKillSwitch(true), "Kill switch enabled");
    } else {
      showModal(
        <ConfirmModal
          strTitle="Disable kill switch?"
          strDescription="Internet traffic may continue outside the VPN if the connection drops."
          strOKButtonText="Disable"
          strCancelButtonText="Cancel"
          bDestructiveWarning
          onOK={() => void runAction(() => setKillSwitch(false), "Kill switch disabled")}
        />,
      );
    }
  };

  const changeTab = (tab: string) => {
    if (busy || signingIn || !["connection", "settings", "account"].includes(tab)) return;
    if (tab !== "account") {
      setPassword("");
      setTotp("");
    }
    lastTab = tab;
    setActiveTab(tab);
  };

  const issue = error && (
        <PanelSection title="Issue">
          <PanelSectionRow>
            <div role="alert" style={{ fontSize: 13, overflowWrap: "anywhere", paddingBottom: 8 }}>{error}</div>
          </PanelSectionRow>
          <PanelSectionRow>
            <DialogButton style={actionStyle} disabled={blocked} onClick={() => {
              if (activeTab !== "connection" && status?.can_start_keyring) void runAction(startKeyring, "Account checked");
              else setRefreshVersion((version) => version + 1);
            }}>
              <FaSyncAlt /> Retry
            </DialogButton>
          </PanelSectionRow>
          {activeTab !== "connection" && status?.diagnostics && (
            <>
              <PanelSectionRow>
                <ToggleField label="Diagnostic details" checked={showDiagnostics} onChange={setShowDiagnostics} />
              </PanelSectionRow>
              {showDiagnostics && <PanelSectionRow>
                <div style={{ fontSize: 12, overflowWrap: "anywhere" }}>
                  {Object.entries(status.diagnostics).map(([label, value]) => <div key={label}>{label}: {value}</div>)}
                </div>
              </PanelSectionRow>}
            </>
          )}
        </PanelSection>
  );

  const connectionView = <>
    <PanelSection>
      <PanelSectionRow>
        <Focusable tabIndex={0} role="group" aria-label="VPN connection status" onFocus={(event) => event.currentTarget.scrollIntoView({ block: "start", behavior: "auto" })} style={{ display: "flex", alignItems: "center", gap: 12, padding: "8px 0 12px", minWidth: 0 }}>
          <ProtonIcon size={28} />
          <div style={{ minWidth: 0, overflowWrap: "anywhere" }}>
            <div style={{ fontSize: 16, fontWeight: 600 }}>
              {!status ? "Checking connection..." : active ? "Connected" : status.connected === false ? "Disconnected" : "Status unavailable"}
            </div>
            <div style={{ fontSize: 12, color: "var(--gpSystemLightGrey, #b8bcbf)", marginTop: 4 }}>
              {status?.server || "Proton VPN"}{status?.protocol ? ` / ${status.protocol}` : ""}
            </div>
          </div>
        </Focusable>
      </PanelSectionRow>
      <PanelSectionRow>
        <DialogButton style={actionStyle} disabled={blocked || status?.connected == null || !!error} onClick={() => void runAction(active ? disconnect : connectionAction, active ? "Disconnected" : "Connected")}>
          {active ? <FaPowerOff /> : <FaBolt />}
          {busy ? "Working..." : active ? "Disconnect" : selectedCountry ? "Connect" : "Quick connect"}
        </DialogButton>
      </PanelSectionRow>
    </PanelSection>
    <PanelSection title="Location">
      <PanelSectionRow>
        <DropdownItem label="Server" layout="below" rgOptions={[{ data: "", label: "Fastest available" }, ...countries.map((country) => ({ data: country.code, label: country.name }))]} selectedOption={selectedCountry} disabled={blocked} menuLabel="VPN location" strDefaultLabel="Fastest available" onChange={(option) => setSelectedCountry(String(option.data))} />
      </PanelSectionRow>
      {active && <PanelSectionRow>
        <DialogButton style={actionStyle} disabled={blocked || !!error} onClick={() => void runAction(connectionAction, selected ? `Connected to ${selected.name}` : "Connected to fastest server")}>
          <FaExchangeAlt /> Switch server
        </DialogButton>
      </PanelSectionRow>}
    </PanelSection>
    {issue}
  </>;

  const accountPrompt = !loadingSettings && status?.signed_in === false && <PanelSection>
    <PanelSectionRow><DialogButton style={actionStyle} onClick={() => changeTab("account")}>Sign in</DialogButton></PanelSectionRow>
  </PanelSection>;
  const settingsView = <>
    {loadingSettings && <PanelSection><PanelSectionRow>Checking settings...</PanelSectionRow></PanelSection>}
    {status?.signed_in && <>
      <PanelSection title="Protection">
        <PanelSectionRow>
          <ToggleField label="Kill switch" description={killSwitch === null ? "Unavailable" : `${killSwitch ? "Standard" : "Off"}${active ? " - disconnect to change" : !canChangeKillSwitch ? " - VPN state unknown" : ""}`} checked={killSwitch === true} disabled={blocked || !!error || killSwitch === null || !canChangeKillSwitch} onChange={changeKillSwitch} />
        </PanelSectionRow>
        <PanelSectionRow>
          <DropdownItem label="NetShield" layout="below" menuLabel="NetShield" strDefaultLabel={status.requires_upgrade?.includes("netshield") ? "VPN Plus required" : "Unavailable"} selectedOption={selectedNetshield ?? status.settings?.netshield ?? undefined} disabled={blocked || !!error || status.settings?.netshield == null} rgOptions={[
            { data: "off", label: "Off" },
            { data: "malware-only", label: "Block malware" },
            { data: "malware-ads-trackers", label: "Block malware, ads and trackers" },
          ]} onChange={(option) => setSelectedNetshield(String(option.data))} />
        </PanelSectionRow>
        {selectedNetshield !== undefined && selectedNetshield !== status.settings?.netshield && <PanelSectionRow>
          <DialogButton style={actionStyle} disabled={blocked || !!error || status.settings?.netshield == null} onClick={() => void runAction(() => setFeature("netshield", selectedNetshield), "NetShield updated")}><FaPowerOff /> Apply NetShield</DialogButton>
        </PanelSectionRow>}
      </PanelSection>
      <PanelSection title="Performance">
        {[["vpn-accelerator", "VPN Accelerator"], ["moderate-nat", "Moderate NAT"]].map(([name, label]) => {
          const value = status.settings?.[name];
          return <PanelSectionRow key={name}>
            <ToggleField label={label} description={status.requires_upgrade?.includes(name) ? "VPN Plus required" : value == null ? "Unavailable" : status.requires_reconnect?.includes(name) && active ? "Applies after reconnect" : undefined} checked={value === "on"} disabled={blocked || !!error || value == null} onChange={(enabled) => {
              if (!blocked && !error && value != null) void runAction(() => setFeature(name, enabled ? "on" : "off"), `${label} updated`);
            }} />
          </PanelSectionRow>;
        })}
      </PanelSection>
      {status.notice && <PanelSection><PanelSectionRow><div role="status">{status.notice}</div></PanelSectionRow></PanelSection>}
    </>}
    {accountPrompt}
    {issue}
  </>;

  const accountView = <>
    {loadingSettings && installation.state !== "running" && <PanelSection><PanelSectionRow>Checking account...</PanelSectionRow></PanelSection>}
    {installation.state === "running" && <PanelSection><PanelSectionRow>
      <div role="status">{({ checking: "Checking installation...", repository: "Preparing Flathub...", installing: "Installing Proton VPN...", verifying: "Verifying Proton VPN..." } as Record<string, string>)[installation.stage ?? ""] ?? "Installing Proton VPN..."}</div>
    </PanelSectionRow></PanelSection>}
    {status?.installed === false && <PanelSection><PanelSectionRow>
      <DialogButton style={actionStyle} disabled={blocked || installation.state === "unknown"} onClick={confirmInstall}><FaDownload /> Install Proton VPN</DialogButton>
    </PanelSectionRow></PanelSection>}
    {status?.signed_in && <PanelSection title="Account">
      <PanelSectionRow>
        <div aria-label="Signed-in account" style={{ fontSize: 14, overflowWrap: "anywhere", minWidth: 0, paddingBottom: 8 }}>
          {status.account_name ?? "Account name unavailable"}
        </div>
      </PanelSectionRow>
      <PanelSectionRow>
        <DialogButton style={actionStyle} disabled={blocked || !!error} onClick={confirmSignOut}><FaSignOutAlt /> Sign out</DialogButton>
      </PanelSectionRow>
    </PanelSection>}

      {status?.installed && status.signed_in === false && !status.error && (
        <PanelSection title="Sign in">
          <PanelSectionRow>
            <TextField
              label="Proton username"
              value={username}
              disabled={blocked}
              onChange={(event) => setUsername(event.currentTarget.value)}
            />
          </PanelSectionRow>
          <PanelSectionRow>
            <TextField
              label="Password"
              {...{ type: "password", autoComplete: "off" }}
              value={password}
              bIsPassword
              bShowCopyAction={false}
              spellCheck={false}
              disabled={blocked}
              onChange={(event) => setPassword(event.currentTarget.value)}
            />
          </PanelSectionRow>
          <PanelSectionRow>
            <TextField
              label="2FA or recovery code"
              {...{ type: "password", autoComplete: "off" }}
              value={totp}
              bIsPassword
              bShowCopyAction={false}
              spellCheck={false}
              disabled={blocked}
              onChange={(event) => setTotp(event.currentTarget.value)}
            />
          </PanelSectionRow>
          <PanelSectionRow>
            <DialogButton
              style={actionStyle}
              disabled={blocked || !username || !password}
              onClick={() => void submitSignIn()}
            >
              {signingIn ? "Signing in..." : "Sign in"}
            </DialogButton>
          </PanelSectionRow>
        </PanelSection>
      )}
    {issue}
  </>;

  return (
    <div className="protonvpn-tabs" style={{ position: "fixed", height: "95%", width: "300px", maxWidth: "100%", marginTop: "-12px", overflow: "hidden" }}>
      <style>{`.protonvpn-tabs [role="tabpanel"] { min-height: 0; padding-left: 8px !important; padding-right: 8px !important; overflow-y: auto; scroll-padding-block: 8px; }`}</style>
      <Tabs activeTab={activeTab} onShowTab={changeTab} tabs={[
        { id: "connection", title: <FaExchangeAlt size={18} role="img" aria-label="Connection" title="Connection" style={{ display: "block" }} />, content: connectionView },
        { id: "settings", title: <FaSlidersH size={18} role="img" aria-label="Settings" title="Settings" style={{ display: "block" }} />, content: settingsView },
        { id: "account", title: <FaUser size={18} role="img" aria-label="Account" title="Account" style={{ display: "block" }} />, content: accountView },
      ]} />
    </div>
  );
}

export default definePlugin(() => ({
  name: "Proton VPN (Unofficial)",
  titleView: <div className={staticClasses.Title} style={{ fontSize: 16 }}>Proton VPN (Unofficial)</div>,
  content: <Content />,
  icon: <ProtonIcon />,
}));
