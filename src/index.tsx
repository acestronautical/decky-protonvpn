import { ButtonItem, Dropdown, PanelSection, PanelSectionRow, staticClasses } from "@decky/ui";
import { callable, definePlugin, toaster } from "@decky/api";
import { useEffect, useState } from "react";
import { FaShieldAlt } from "react-icons/fa";

type ProtonCountry = {
  code: string;
  name: string;
};

type ProtonStatus = {
  installed: boolean;
  signed_in: boolean;
  connected: boolean;
  server?: string;
  protocol?: string;
  error?: string;
};

type CountryList = {
  signed_in: boolean;
  countries: ProtonCountry[];
  error?: string;
};

const getStatus = callable<[], ProtonStatus>("get_status");
const getCountries = callable<[], CountryList>("get_countries");
const connectCountry = callable<[countryCode: string], ProtonStatus>(
  "connect_country",
);
const disconnect = callable<[], ProtonStatus>("disconnect");

function Content() {
  const [status, setStatus] = useState<ProtonStatus>();
  const [countries, setCountries] = useState<ProtonCountry[]>([]);
  const [selectedCountry, setSelectedCountry] = useState("");
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const [loadingCountries, setLoadingCountries] = useState(false);

  const refreshStatus = async () => {
    setBusy(true);
    try {
      const result = await getStatus();
      setStatus(result);
      setError(result.error);
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  };

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
      toaster.toast({ title: "Proton VPN", body: success });
    } catch (reason) {
      const message = String(reason);
      setError(message);
      toaster.toast({ title: "Proton VPN", body: message });
    } finally {
      setBusy(false);
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
              : !status.installed
                ? "Proton VPN is not installed. Install it from Discover in Desktop Mode."
                : status.error
                  ? "Proton VPN CLI is unavailable"
                  : !status.signed_in
                    ? "Proton VPN CLI is signed out"
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
        <PanelSectionRow>
          <ButtonItem disabled={busy} onClick={() => void refreshStatus()}>
            Refresh Proton VPN status
          </ButtonItem>
        </PanelSectionRow>
      </PanelSection>

      {status?.installed && !status.signed_in && !status.error && (
        <PanelSection title="Sign in">
          <PanelSectionRow>
            <div>
              Close the Proton VPN desktop app. In Desktop Mode, open Konsole and run:
            </div>
          </PanelSectionRow>
          <PanelSectionRow>
            <code>flatpak run --command=protonvpn com.protonvpn.www signin &lt;username&gt;</code>
          </PanelSectionRow>
          <PanelSectionRow>
            <div>
              Enter your password and any verification only in Proton CLI's terminal prompts. Decky never receives or stores them.
            </div>
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
