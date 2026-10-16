import asyncio
import hashlib
import inspect
import json
import re
import runpy
import sys


UPSTREAM_ROUTE_APPLY_SHA256 = "96c9a79892adc7f5a2f561b69217907764c4fc8655769bf99d656cd9366315c1"
UPSTREAM_TASK_WAIT_SHA256 = "b049cf4e79239d1c48d9745b10f09a02b04211f9fcb4b9d7cbf4d25a4a949111"
UPSTREAM_KEYRING_GET_SHA256 = "5f2797e5d201e25c5502d5400301536028e5b8a6cc89e696c845765ab182a8d1"


def install_keyring_read_fix(module) -> bool:
    backend = module.KeyringBackendLinuxSecretService
    try:
        source = inspect.getsource(backend._get_item)
    except (AttributeError, OSError, TypeError):
        return False
    if hashlib.sha256(source.encode()).hexdigest() != UPSTREAM_KEYRING_GET_SHA256:
        return False

    def get_item(self, key):
        try:
            stored_data = self._backend.get_password(self.KEYRING_SERVICE, key)
        except module.keyring.errors.KeyringLocked:
            raise module.KeyringLocked("Keyring is locked") from None
        except module.keyring.errors.KeyringError:
            raise module.KeyringError("Secure keyring read failed; saved credentials were not changed") from None
        if stored_data is None:
            raise KeyError(key)
        try:
            return json.loads(stored_data)
        except json.JSONDecodeError:
            try:
                return json.loads(stored_data.replace("\n", "\\n"))
            except json.JSONDecodeError:
                raise module.KeyringError("Secure keyring returned invalid data; saved credentials were not changed") from None

    backend._get_item = get_item
    return True


def install_route_snapshot_fix(nm_client, nm) -> bool:
    try:
        source = inspect.getsource(nm_client._apply_connection_async)
    except (AttributeError, OSError, TypeError):
        return False
    if hashlib.sha256(source.encode()).hexdigest() != UPSTREAM_ROUTE_APPLY_SHA256:
        return False

    @classmethod
    def apply_snapshot(cls, active_connection, future):
        cls._assert_running_on_glib_loop_thread()
        connection = active_connection.get_connection()
        snapshot = nm.SimpleConnection.new_clone(connection)
        device = active_connection.get_devices()[0]

        def reapplied(device, result, _data=None):
            try:
                device.reapply_finish(result)
                future.set_result(None)
            except Exception as error:
                future.set_exception(error)

        def committed(connection, result, _data=None):
            try:
                connection.commit_changes_finish(result)
                device.reapply_async(
                    snapshot, version_id=0, flags=0,
                    cancellable=None, callback=reapplied,
                )
            except Exception as error:
                future.set_exception(error)

        connection.commit_changes_async(
            save_to_disk=False, cancellable=None, callback=committed,
        )

    nm_client._apply_connection_async = apply_snapshot
    return True


def install_disconnect_cleanup_fix(server) -> bool:
    try:
        source = inspect.getsource(server.wait_for_current_tasks)
    except (AttributeError, OSError, TypeError):
        return False
    if hashlib.sha256(source.encode()).hexdigest() != UPSTREAM_TASK_WAIT_SHA256:
        return False

    async def wait_for_current_tasks(timeout=10):
        current = asyncio.current_task()
        tasks = [task for task in asyncio.all_tasks() if task is not current]
        results = await asyncio.wait_for(
            asyncio.gather(*tasks, return_exceptions=True), timeout,
        )
        for result in results:
            if isinstance(result, BaseException) and not isinstance(result, asyncio.CancelledError):
                raise result

    server.wait_for_current_tasks = wait_for_current_tasks
    return True


async def read_panel_snapshot(controller, features) -> dict:
    result = {"signed_in": bool(controller.is_logged_in), "account_name": None}
    if not result["signed_in"]:
        return result
    try:
        account_name = controller.account_name
        if isinstance(account_name, str) and re.fullmatch(r"[A-Za-z0-9._+@-]{1,254}", account_name):
            result["account_name"] = account_name
    except Exception:
        pass
    settings = {}
    requires_upgrade = []
    try:
        for feature in features:
            if not feature.available_on_free_tier and controller.user_on_free_tier:
                settings[feature.command] = None
                requires_upgrade.append(feature.command)
            else:
                value = await controller.get_feature_setting(feature)
                settings[feature.command] = feature.click_type.to_str(value)
        result["settings"] = settings
        result["requires_upgrade"] = requires_upgrade
        result["requires_reconnect"] = [feature.command for feature in features if getattr(feature, "requires_restart", False)]
    except Exception:
        result["settings_error"] = "Proton settings could not be read"
    return result


def install_panel_snapshot(account, features) -> None:
    async def snapshot(ctx):
        controller = await account.Controller.create(params=ctx.obj, click_ctx=ctx)
        print(json.dumps(await read_panel_snapshot(controller, features)))

    account.info.callback = account.click.pass_context(account.run_async(snapshot))


def main() -> None:
    from proton.keyring_linux.secretservice import secretservice_backend

    if not install_keyring_read_fix(secretservice_backend):
        raise RuntimeError("Unsupported Proton keyring implementation; no CLI command was run")
    if sys.argv[1:] == ["panel-snapshot"]:
        from proton.vpn.cli.commands import account, feature_setting_definitions as features

        install_panel_snapshot(account, (
            features.KILLSWITCH_FEATURE, features.NETSHIELD_FEATURE,
            features.VPN_ACCELERATOR_FEATURE, features.MODERATE_NAT_FEATURE,
        ))
        sys.argv[1:] = ["info"]
    if sys.argv[1:2] in (["connect"], ["disconnect"], ["signout"]) or sys.argv[1:3] == ["config", "set"]:
        from proton.vpn.backend.networkmanager.killswitch.wireguard.nmclient import NMClient, NM

        install_route_snapshot_fix(NMClient, NM)
    if sys.argv[1:2] == ["disconnect"]:
        from proton.vpn.cli.commands import server

        install_disconnect_cleanup_fix(server)
    sys.argv[0] = "protonvpn"
    runpy.run_path("/app/bin/protonvpn", run_name="__main__")


if __name__ == "__main__":
    main()