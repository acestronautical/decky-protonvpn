import {
  ButtonItem,
  Dropdown,
  PanelSection,
  PanelSectionRow,
  TextField,
  staticClasses,
} from "@decky/ui";
import { callable, definePlugin, toaster } from "@decky/api";
import { useEffect, useRef, useState } from "react";
import { FaShieldAlt } from "react-icons/fa";
import { encodeSignIn, encryptSignIn } from "./signin";

type ProtonCountry = {
  code: string;
  name: string;
};

type ProtonStatus = {
  installed: boolean | null;
  signed_in: boolean | null;
  connected: boolean | null;
  tunnel_active?: boolean | null;
  server?: string;
  protocol?: string;
  error?: string;
  diagnostics?: Record<string, string>;
  can_start_keyring?: boolean;
};

type CountryList = {
  signed_in: boolean;
  countries: ProtonCountry[];
  error?: string;
};

type SignInSession = {
  session_id: string;
  public_key: string;
};

type SignInError = { error: string };

const getStatus = callable<[], ProtonStatus>("get_status");
const startKeyring = callable<[], ProtonStatus>("start_keyring");
const getCountries = callable<[], CountryList>("get_countries");
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

function Content() {
  const [status, setStatus] = useState<ProtonStatus>();
  const [countries, setCountries] = useState<ProtonCountry[]>([]);
  const [selectedCountry, setSelectedCountry] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const [loadingCountries, setLoadingCountries] = useState(false);
  const [signingIn, setSigningIn] = useState(false);
  const mounted = useRef(true);
  const signInRequest = useRef<{
    plaintext: Uint8Array;
    sessionId?: string;
  } | undefined>(undefined);

  const refreshStatus = async (action = getStatus) => {
    setBusy(true);
    try {
      const result = await action();
      setStatus(result);
      setError(result.error);
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
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
    let mounted = true;
    void getStatus()
      .then((result) => {
        if (mounted) {
          setStatus(result);
          setError(result.error);
        }
      })
      .catch((reason) => {
        if (mounted) {
          setError(String(reason));
        }
      });
    return () => {
      mounted = false;
    };
  }, []);

  useEffect(() => {
    let mounted = true;
    if (!status?.signed_in || status.error) {
      setCountries([]);
      setSelectedCountry("");
      setLoadingCountries(false);
      return;
    }

    setLoadingCountries(true);
    void getCountries()
      .then((result) => {
        if (!mounted) {
          return;
        }
        setCountries(result.countries);
        setError(result.error);
        setSelectedCountry((current) =>
          result.countries.some((country) => country.code === current)
            ? current
            : result.countries.find((country) => country.code === "US")?.code ??
              result.countries[0]?.code ??
              "",
        );
      })
      .catch((reason) => {
        if (mounted) {
          setError(String(reason));
        }
      })
      .finally(() => {
        if (mounted) {
          setLoadingCountries(false);
        }
      });

    return () => {
      mounted = false;
    };
  }, [status?.signed_in, status?.error]);

  const runAction = async (action: () => Promise<ProtonStatus>, success: string) => {
    setBusy(true);
    setError(undefined);
    try {
      const result = await action();
      setStatus(result);
      setError(result.error);
      toaster.toast({ title: "Proton VPN", body: result.error ?? success });
    } catch (reason) {
      const message = String(reason);
      setError(message);
      toaster.toast({ title: "Proton VPN", body: message });
    } finally {
      setBusy(false);
    }
  };

  const submitSignIn = async () => {
    if (signInRequest.current || busy) {
      return;
    }
    setSigningIn(true);
    setError(undefined);
    try {
      if (!globalThis.crypto?.subtle) {
        throw new Error("Secure sign-in is unavailable here; use Desktop Mode sign-in");
      }
      const request: { plaintext: Uint8Array; sessionId?: string } = {
        plaintext: encodeSignIn({ username, password, totp }),
      };
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
      setStatus(result);
      setError(result.error);
      if (result.signed_in) {
        setUsername("");
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

  const selected = countries.find((country) => country.code === selectedCountry);

  return (
    <>
      <PanelSection title="Status">
        <PanelSectionRow>
          <div>
            {!status
              ? "Checking Proton VPN CLI..."
              : status.tunnel_active === true && status.connected !== true
                ? "VPN tunnel active; Proton status unavailable"
                : status.error
                ? "Proton VPN status is unavailable"
                : !status.installed
                  ? "Proton VPN is not installed. Install it from Discover in Desktop Mode."
                  : !status.signed_in
                    ? "Proton VPN CLI is signed out; VPN state is unknown"
                    : status.connected
                      ? `Connected: ${status.server || "Proton VPN"}`
                      : "Disconnected"}
          </div>
        </PanelSectionRow>
        {status?.protocol && (
          <PanelSectionRow>
            <div>Protocol: {status.protocol}</div>
          </PanelSectionRow>
        )}
        {error && (
          <PanelSectionRow>
            <div>{error}</div>
          </PanelSectionRow>
        )}
        {status?.can_start_keyring && (
          <PanelSectionRow>
            <ButtonItem disabled={busy || signingIn} onClick={() => void refreshStatus(startKeyring)}>
              Start existing keyring service
            </ButtonItem>
          </PanelSectionRow>
        )}
        {status?.diagnostics && (
          <PanelSectionRow>
            <div style={{ fontSize: 12, overflowWrap: "anywhere" }}>
              {Object.entries(status.diagnostics).map(([label, value]) => (
                <div key={label}>{label}: {value}</div>
              ))}
            </div>
          </PanelSectionRow>
        )}
        <PanelSectionRow>
          <ButtonItem disabled={busy || signingIn} onClick={() => void refreshStatus()}>
            Refresh Proton VPN status
          </ButtonItem>
        </PanelSectionRow>
      </PanelSection>

      {status?.installed && status.signed_in === false && !status.error && (
        <PanelSection title="Sign in">
          <PanelSectionRow>
            <TextField
              label="Proton username"
              value={username}
              disabled={signingIn}
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
              disabled={signingIn}
              onChange={(event) => setPassword(event.currentTarget.value)}
            />
          </PanelSectionRow>
          <PanelSectionRow>
            <TextField
              label="Authenticator or recovery code (if required)"
              {...{ type: "password", autoComplete: "off" }}
              value={totp}
              bIsPassword
              bShowCopyAction={false}
              spellCheck={false}
              disabled={signingIn}
              onChange={(event) => setTotp(event.currentTarget.value)}
            />
          </PanelSectionRow>
          <PanelSectionRow>
            <ButtonItem
              disabled={busy || signingIn || !username || !password}
              onClick={() => void submitSignIn()}
            >
              {signingIn ? "Signing in..." : "Sign in"}
            </ButtonItem>
          </PanelSectionRow>
        </PanelSection>
      )}

      {status?.installed && status.signed_in && !status.error && (
        <PanelSection title="Proton VPN Location">
          {loadingCountries ? (
            <PanelSectionRow>
              <div>Loading Proton VPN countries...</div>
            </PanelSectionRow>
          ) : countries.length === 0 ? (
            <PanelSectionRow>
              <div>No countries are available for this Proton account.</div>
            </PanelSectionRow>
          ) : (
            <PanelSectionRow>
              <Dropdown
                rgOptions={countries.map((country) => ({
                  data: country.code,
                  label: country.name,
                }))}
                selectedOption={selectedCountry}
                disabled={busy}
                menuLabel="Choose a Proton VPN country"
                strDefaultLabel="Choose country"
                onChange={(option) => setSelectedCountry(String(option.data))}
              />
            </PanelSectionRow>
          )}
          <PanelSectionRow>
            <ButtonItem
              disabled={busy || !selectedCountry}
              onClick={() => {
                if (!selected || !selectedCountry) {
                  return;
                }
                void runAction(
                  () => connectCountry(selectedCountry),
                  `${status.connected ? "Switching to" : "Connecting to"} ${selected.name}`,
                );
              }}
            >
              {status.connected ? `Switch to ${selected?.name ?? "country"}` : `Connect to ${selected?.name ?? "country"}`}
            </ButtonItem>
          </PanelSectionRow>
          {status.connected && (
            <PanelSectionRow>
              <ButtonItem
                disabled={busy}
                onClick={() =>
                  void runAction(disconnect, "Disconnected through Proton VPN CLI")
                }
              >
                Disconnect
              </ButtonItem>
            </PanelSectionRow>
          )}
        </PanelSection>
      )}
    </>
  );
}

export default definePlugin(() => ({
  name: "Proton VPN",
  titleView: <div className={staticClasses.Title}>Proton VPN</div>,
  content: <Content />,
  icon: <FaShieldAlt />,
}));
