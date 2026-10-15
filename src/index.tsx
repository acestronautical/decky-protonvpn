import { PanelSection, PanelSectionRow, ToggleField, staticClasses } from "@decky/ui";
import { callable, definePlugin, toaster } from "@decky/api";
import { useEffect, useState } from "react";
import { FaShieldAlt } from "react-icons/fa";

type ProtonConnection = {
  uuid: string;
  name: string;
  type: string;
  active: boolean;
};

type ConnectionSnapshot = {
  installed: boolean;
  connected: boolean;
  connections: ProtonConnection[];
  error?: string;
};

const getConnections = callable<[], ConnectionSnapshot>("get_connections");
const toggleConnection = callable<[profileUuid: string], ConnectionSnapshot>(
  "toggle_connection",
);

function Content() {
  const [snapshot, setSnapshot] = useState<ConnectionSnapshot>();
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let mounted = true;
    const refresh = async () => {
      try {
        const result = await getConnections();
        if (mounted) {
          setSnapshot(result);
          setError(result.error);
        }
      } catch (reason) {
        if (mounted) {
          setError(String(reason));
        }
      }
    };

    void refresh();
    const interval = window.setInterval(() => void refresh(), 5000);
    return () => {
      mounted = false;
      window.clearInterval(interval);
    };
  }, []);

  const onConnectionChange = async (
    connection: ProtonConnection,
    enabled: boolean,
  ) => {
    if (busy || enabled === connection.active) {
      return;
    }

    setBusy(true);
    try {
      const result = await toggleConnection(connection.uuid);
      setSnapshot(result);
      setError(result.error);
      const connected = result.connections.some(
        (item) => item.uuid === connection.uuid && item.active,
      );
      toaster.toast({
        title: "Proton VPN",
        body: `${connection.name} ${connected ? "connected" : "disconnected"}`,
      });
    } catch (reason) {
      const message = String(reason);
      setError(message);
      toaster.toast({ title: "Proton VPN", body: message });
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <PanelSection title="Status">
        <PanelSectionRow>
          <div>
            {!snapshot
              ? "Checking Proton VPN..."
              : !snapshot.installed
                ? "Proton VPN is not installed. Install it from Discover in Desktop Mode."
                : snapshot.connected
                  ? `Connected: ${snapshot.connections.find((connection) => connection.active)?.name ?? "Proton VPN"}`
                  : "Disconnected"}
          </div>
        </PanelSectionRow>
        {error && (
          <PanelSectionRow>
            <div>{error}</div>
          </PanelSectionRow>
        )}
      </PanelSection>

      {snapshot?.installed && (
        <PanelSection title="Proton VPN Connections">
          {snapshot.connections.length === 0 ? (
            <PanelSectionRow>
              <div>
                Open Proton VPN in Desktop Mode, sign in if needed, and connect once.
                The saved connection will appear here.
              </div>
            </PanelSectionRow>
          ) : (
            snapshot.connections.map((connection) => (
              <PanelSectionRow key={connection.uuid}>
                <ToggleField
                  checked={connection.active}
                  disabled={busy}
                  label={connection.name}
                  description={connection.type}
                  onChange={(enabled) =>
                    void onConnectionChange(connection, enabled)
                  }
                />
              </PanelSectionRow>
            ))
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
