import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import test from "node:test";
import { runInNewContext } from "node:vm";
import renderer from "react-test-renderer";
import ts from "typescript";

const require = createRequire(import.meta.resolve("react-test-renderer"));
const { act, create } = renderer;
const compiled = ts.transpileModule(readFileSync(new URL("../src/index.tsx", import.meta.url), "utf8"), {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true },
}).outputText;

function panelHarness({ detailsGate } = {}) {
  const calls = [];
  const modals = [];
  let killSwitch = false;
  let settings = { "kill-switch": "off", netshield: "off", "vpn-accelerator": "on", "moderate-nat": "off" };
  let status = { installed: true, signed_in: true, connected: true, tunnel_active: true };
  const controls = Object.fromEntries([
    "ConfirmModal", "DialogButton", "DropdownItem", "Focusable", "PanelSection", "PanelSectionRow", "TextField", "ToggleField",
  ].map(name => [name, name]));
  const modules = {
    react: require("react"),
    "react/jsx-runtime": require("react/jsx-runtime"),
    "@decky/ui": {
      ...controls, staticClasses: {}, showModal: modal => modals.push(modal),
      Tabs: props => require("react").createElement("Tabs", props, props.tabs.find(tab => tab.id === props.activeTab)?.content),
    },
    "@decky/api": {
      definePlugin: factory => factory,
      toaster: { toast: () => {} },
      callable: name => async (...args) => {
        calls.push([name, ...args]);
        assert.ok(["get_connection_status", "get_status", "connect_country", "disconnect", "quick_connect", "signout", "set_kill_switch", "set_feature"].includes(name), `Unexpected RPC ${name}`);
        if (name === "get_connection_status") return { connected: status.connected, tunnel_active: status.tunnel_active, server: "", protocol: "WireGuard" };
        if (name === "get_status" && detailsGate) await detailsGate;
        if (name === "set_kill_switch") {
          killSwitch = args[0];
          settings["kill-switch"] = killSwitch ? "standard" : "off";
        }
        if (name === "set_feature") settings[args[0]] = args[1];
        return { ...status, kill_switch: killSwitch, settings: { ...settings } };
      },
    },
    "react-icons/fa": Object.fromEntries([
      "FaBolt", "FaExchangeAlt", "FaPowerOff", "FaSignOutAlt", "FaSlidersH", "FaSyncAlt", "FaUser",
    ].map(name => [name, () => null])),
    "./signin": { cachedUsername: () => "" },
    "../protonvpn-dark.png": "protonvpn.png",
    "../py_modules/protonvpn/countries.json": JSON.parse(readFileSync(new URL("../py_modules/protonvpn/countries.json", import.meta.url), "utf8")),
  };
  const module = { exports: {} };
  runInNewContext(compiled, {
    exports: module.exports,
    module,
    require: name => {
      assert.ok(Object.hasOwn(modules, name), `Unexpected import: ${name}`);
      return modules[name];
    },
  });
  const plugin = module.exports.default();
  const content = plugin.content;
  let panel;
  return {
    calls,
    modals,
    icon: plugin.icon,
    setStatus: next => { status = next; },
    setSettings: next => { settings = next; },
    async open() { await act(async () => { panel = create(content); }); },
    close() { act(() => panel.unmount()); },
    async tab(id) { await act(async () => panel.root.findByType("Tabs").props.onShowTab(id)); },
    activeTab() { return panel.root.findByType("Tabs").props.activeTab; },
    tabs() { return panel.root.findByType("Tabs").props.tabs; },
    frame() { return panel.root.findByProps({ className: "protonvpn-tabs" }); },
    header() { return panel.root.findByType("Focusable"); },
    country() { return panel.root.findByType("DropdownItem").props.selectedOption; },
    selectionHandler() { return panel.root.findByType("DropdownItem").props.onChange; },
    select(country) { act(() => panel.root.findByType("DropdownItem").props.onChange({ data: country })); },
    killSwitch() { return panel.root.findAllByType("ToggleField").find(toggle => toggle.props.label === "Kill switch"); },
    toggle(label) { return panel.root.findAllByType("ToggleField").find(toggle => toggle.props.label === label); },
    netshield() { return panel.root.findByType("DropdownItem"); },
    button(label) {
      return panel.root.findAllByType("DialogButton").find(button =>
        button.children.filter(child => typeof child === "string").join("").trim() === label);
    },
  };
}

test("tabs use labeled icons and inherit the available panel height", async () => {
  const panel = panelHarness();
  await panel.open();
  assert.deepEqual(Array.from(panel.tabs(), tab => tab.title.props["aria-label"]), ["Connection", "Settings", "Account"]);
  for (const tab of panel.tabs()) {
    assert.equal(tab.title.props.title, tab.title.props["aria-label"]);
    assert.equal(tab.title.props.children.props.size, 20);
    assert.equal(tab.title.props.children.props["aria-hidden"], "true");
  }
  assert.equal(panel.frame().props.style.height, "100%");
  assert.equal(panel.frame().props.style.minHeight, 0);
  assert.deepEqual(panel.calls, [["get_connection_status"]]);
  panel.close();
});

test("Canada survives picker/panel remount and only Switch server connects", async () => {
  const panel = panelHarness();
  await panel.open();
  panel.select("CA");
  assert.equal(panel.country(), "CA");
  panel.close();
  await panel.open();
  assert.equal(panel.country(), "CA");
  assert.deepEqual(panel.calls.map(call => call[0]), ["get_connection_status", "get_connection_status"]);
  const button = panel.button("Switch server");
  assert.ok(button);
  assert.equal(button.props.disabled, false);
  await act(async () => button.props.onClick());
  assert.deepEqual(panel.calls.slice(2), [["connect_country", "CA"]]);
  panel.close();
});

test("remount refreshes tunnel state and Fastest remains an explicit action", async () => {
  const panel = panelHarness();
  await panel.open();
  panel.select("CA");
  panel.select("");
  panel.close();
  panel.setStatus({ installed: true, signed_in: true, connected: false, tunnel_active: false });
  await panel.open();
  assert.equal(panel.country(), "");
  assert.equal(panel.button("Switch server"), undefined);
  assert.equal(panel.button("Disconnect"), undefined);
  assert.equal(panel.calls.length, 2);
  const button = panel.button("Quick connect");
  assert.ok(button);
  assert.equal(button.props.disabled, false);
  await act(async () => button.props.onClick());
  assert.deepEqual(panel.calls.slice(2), [["quick_connect"]]);
  panel.close();
});

test("a picker callback from the closed panel updates the reopened panel", async () => {
  const panel = panelHarness();
  await panel.open();
  const chooseCountry = panel.selectionHandler();
  panel.close();
  await panel.open();
  act(() => chooseCountry({ data: "CA" }));
  assert.equal(panel.country(), "CA");
  assert.equal(panel.calls.length, 2);
  await act(async () => panel.button("Switch server").props.onClick());
  assert.deepEqual(panel.calls.slice(2), [["connect_country", "CA"]]);
  panel.close();
});

test("kill-switch toggle refuses connected or unknown state without actions", async () => {
  for (const [connected, tunnel_active, explanation] of [
    [true, true, "disconnect to change"],
    [false, true, "disconnect to change"],
    [false, null, "VPN state unknown"],
    [null, false, "VPN state unknown"],
  ]) {
    const panel = panelHarness();
    panel.setStatus({ installed: true, signed_in: true, connected, tunnel_active });
    await panel.open();
    await panel.tab("settings");
    const toggle = panel.killSwitch();
    assert.equal(toggle.props.disabled, true);
    assert.ok(toggle.props.description.includes(explanation));
    await act(async () => {
      toggle.props.onChange(true);
      toggle.props.onChange(false);
    });
    assert.deepEqual(panel.calls.map(call => call[0]), ["get_connection_status", "get_status"]);
    assert.equal(panel.modals.length, 0);
    assert.equal(panel.killSwitch().props.checked, false);
    panel.close();
  }
});

test("disconnected kill-switch changes use readback and disabling requires confirmation", async () => {
  const panel = panelHarness();
  panel.setStatus({ installed: true, signed_in: true, connected: false, tunnel_active: false });
  await panel.open();
  await panel.tab("settings");
  assert.equal(panel.killSwitch().props.disabled, false);
  await act(async () => panel.killSwitch().props.onChange(true));
  assert.equal(panel.killSwitch().props.checked, true);
  assert.deepEqual(panel.calls.slice(2), [["set_kill_switch", true]]);
  await act(async () => panel.killSwitch().props.onChange(false));
  assert.equal(panel.modals.length, 1);
  assert.equal(panel.killSwitch().props.checked, true);
  assert.equal(panel.calls.length, 3);
  await act(async () => panel.modals[0].props.onOK());
  assert.equal(panel.killSwitch().props.checked, false);
  assert.deepEqual(panel.calls.slice(2), [["set_kill_switch", true], ["set_kill_switch", false]]);
  panel.close();
});

test("native tabs load Proton details lazily and preserve the connection selection", async () => {
  const panel = panelHarness();
  await panel.open();
  assert.equal(panel.activeTab(), "connection");
  panel.select("CA");
  assert.deepEqual(panel.calls, [["get_connection_status"]]);
  await panel.tab("settings");
  assert.deepEqual(panel.calls, [["get_connection_status"], ["get_status"]]);
  await panel.tab("account");
  assert.ok(panel.button("Sign out"));
  await panel.tab("connection");
  assert.equal(panel.country(), "CA");
  assert.deepEqual(panel.calls, [["get_connection_status"], ["get_status"], ["get_status"], ["get_connection_status"]]);
  panel.close();
});

test("tab changes share an in-flight details request and keep connection readable", async () => {
  let release;
  const detailsGate = new Promise(resolve => { release = resolve; });
  const panel = panelHarness({ detailsGate });
  await panel.open();
  await panel.tab("settings");
  await panel.tab("account");
  await panel.tab("connection");
  assert.deepEqual(panel.calls, [["get_connection_status"], ["get_status"], ["get_connection_status"]]);
  assert.ok(panel.button("Disconnect"));
  assert.equal(panel.button("Disconnect").props.disabled, true);
  await act(async () => release());
  assert.equal(panel.button("Disconnect").props.disabled, false);
  panel.close();
});

test("header focus returns to the top and sidebar icon inherits native sizing", async () => {
  const panel = panelHarness();
  await panel.open();
  let scroll;
  panel.header().props.onFocus({ currentTarget: { scrollIntoView: options => { scroll = options; } } });
  assert.equal(scroll.block, "start");
  assert.equal(panel.header().props.tabIndex, 0);
  let icon;
  act(() => { icon = create(panel.icon); });
  assert.equal(icon.root.findByType("img").props.style.width, "1em");
  act(() => icon.unmount());
  panel.close();
});

test("NetShield survives remount and only Apply changes the setting", async () => {
  const panel = panelHarness();
  await panel.open();
  await panel.tab("settings");
  act(() => panel.netshield().props.onChange({ data: "malware-only" }));
  panel.close();
  await panel.open();
  assert.equal(panel.activeTab(), "settings");
  assert.equal(panel.netshield().props.selectedOption, "malware-only");
  assert.equal(panel.calls.filter(call => call[0] === "set_feature").length, 0);
  await act(async () => panel.button("Apply NetShield").props.onClick());
  assert.deepEqual(panel.calls.at(-1), ["set_feature", "netshield", "malware-only"]);
  assert.equal(panel.netshield().props.selectedOption, "malware-only");
  assert.equal(panel.button("Apply NetShield"), undefined);
  panel.close();
});

test("performance toggles use explicit settings actions and paid controls stay disabled", async () => {
  const panel = panelHarness();
  await panel.open();
  await panel.tab("settings");
  await act(async () => panel.toggle("Moderate NAT").props.onChange(true));
  assert.deepEqual(panel.calls.at(-1), ["set_feature", "moderate-nat", "on"]);
  assert.equal(panel.toggle("Moderate NAT").props.checked, true);
  panel.close();
  panel.setSettings({ "kill-switch": "off", netshield: null, "vpn-accelerator": null, "moderate-nat": null });
  panel.setStatus({ installed: true, signed_in: true, connected: false, tunnel_active: false, requires_upgrade: ["netshield", "vpn-accelerator", "moderate-nat"] });
  await panel.open();
  assert.equal(panel.netshield().props.disabled, true);
  assert.equal(panel.toggle("VPN Accelerator").props.disabled, true);
  assert.equal(panel.toggle("Moderate NAT").props.description, "VPN Plus required");
  const count = panel.calls.length;
  await act(async () => panel.toggle("Moderate NAT").props.onChange(true));
  assert.equal(panel.calls.length, count);
  panel.close();
});