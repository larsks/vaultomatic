import itertools
import logging
import threading
import time

import hvac

from .kubernetes import api, watch, ApiException
from .keystore import Keystore

LOG = logging.getLogger(__name__)


class Vault(threading.Thread):
    max_attempts = 10
    base_interval = 1.5
    healthy_interval = 10

    def __init__(self, addr, ks):
        super().__init__(daemon=True)
        self.addr = addr
        self.ks = ks
        self.quit = False
        self.client = hvac.Client(addr, timeout=10)
        self.attempts = 0
        self.healthy = False

        self.start()

    def check(self):
        LOG.debug("checking status of %s", self)
        self.attempts += 1
        try:
            status = self.client.seal_status

            if not status["initialized"]:
                self.healthy = False
                LOG.info("%s is not initialized", self)
                return False

            if status["sealed"]:
                self.healthy = False
                LOG.info("%s is sealed", self)
                self.client.sys.submit_unseal_keys(self.ks.unseal_keys)
                return False

            if not self.healthy:
                LOG.info("%s is unsealed", self)

            self.healthy = True
            self.attempts = 0
            return True
        except Exception as err:
            LOG.warning("failed to communicate with %s: %s", self, err)
            return False

    def run(self):
        LOG.info("start monitoring %s", self)
        while not self.quit:
            interval = self.base_interval ** min(self.max_attempts, self.attempts)

            if not self.ks.keys:
                LOG.warning("%s waiting for keys", self)
                self.attempts += 1
            elif self.check():
                interval = self.healthy_interval
            else:
                LOG.debug("next check in %d seconds", interval)

            time.sleep(interval)
        LOG.info("no longer monitoring %s", self)

    def stop(self):
        self.quit = True

    def __str__(self):
        return f"<vault {self.addr}>"


class Monitor(threading.Thread):
    def __init__(self, ks: Keystore, namespace, label_selector):
        super().__init__(daemon=True)

        self.ks = ks
        self.namespace = namespace
        self.label_selector = label_selector

        self.vaults = {}
        self.quit = False
        self.watcher = watch.Watch()
        self.healthy = False

    def run(self):
        LOG.info("starting vault monitor")
        while not self.quit:
            try:
                for event in self.watcher.stream(
                    api.list_namespaced_pod,
                    self.namespace,
                    label_selector=self.label_selector,
                    timeout_seconds=5,
                ):
                    addr = f"http://{event['object'].metadata.name}.vault-internal:8200"
                    if event["type"] == "ADDED":
                        if addr not in self.vaults:
                            LOG.info("vault %s added", addr)
                            self.vaults[addr] = Vault(addr, self.ks)
                    elif event["type"] == "DELETED":
                        if addr in self.vaults:
                            LOG.info("vault %s removed", addr)
                            vault = self.vaults.pop(addr)
                            vault.stop()
                    else:
                        LOG.debug("ignoring event %s", event["type"])

                grouped = {
                    k: list(v)
                    for k, v in itertools.groupby(
                        sorted(self.vaults.values(), key=lambda vault: vault.healthy),
                        lambda vault: vault.healthy,
                    )
                }

                if False in grouped:
                    self.healthy = False
                    LOG.warning(
                        "%d of %d vaults are unhealthy",
                        len(grouped[False]),
                        len(self.vaults),
                    )
                elif not self.healthy:
                    self.healthy = True
                    LOG.warning("all %d vaults are healthy", len(grouped[True]))
            except ApiException as err:
                if err.status == 410:
                    LOG.warning("watch expired")
                else:
                    LOG.warning("unexpected api error in discovery thread: %s", err)
                    time.sleep(5)

        LOG.warning("stopping vault monitor")
        for vault in self.vaults.values():
            vault.stop()

    def stop(self):
        self.quit = True
        self.join()
