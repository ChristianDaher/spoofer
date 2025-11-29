'use client';

import { useState, useEffect, useCallback } from 'react';

const API = 'http://localhost:8000';

interface NetworkInfo {
  interface: string;
  ip: string;
  mac: string;
  gateway_ip: string;
  gateway_mac: string;
  network: string;
}

interface Device {
  ip: string;
  mac: string;
  hostname: string | null;
  is_gateway: boolean;
}

interface DeviceStats {
  ip: string;
  mac: string;
  hostname: string | null;
  status: string;
  bandwidth_limit_kbps: number | null;
  download_rate_mbps: number;
  upload_rate_mbps: number;
  total_download_mb: number;
  total_upload_mb: number;
}

interface SpooferStatus {
  running: boolean;
  target_count: number;
  targets: string[];
}

export default function Home() {
  const [networkInfo, setNetworkInfo] = useState<NetworkInfo | null>(null);
  const [devices, setDevices] = useState<Device[]>([]);
  const [stats, setStats] = useState<DeviceStats[]>([]);
  const [spooferStatus, setSpooferStatus] = useState<SpooferStatus>({
    running: false,
    target_count: 0,
    targets: [],
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [limitInput, setLimitInput] = useState<{ [key: string]: string }>({});

  const fetchNetworkInfo = useCallback(async () => {
    try {
      const res = await fetch(`${API}/api/network/info`);
      if (res.ok) setNetworkInfo(await res.json());
    } catch (e) {
      console.error('fetch network info failed:', e);
    }
  }, []);

  const scanNetwork = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API}/api/network/scan`);
      if (res.ok) {
        setDevices(await res.json());
      } else {
        setError('scan failed');
      }
    } catch (e) {
      setError('backend not reachable');
    }
    setLoading(false);
  };

  const fetchStatus = useCallback(async () => {
    try {
      const res = await fetch(`${API}/api/spoofer/status`);
      if (res.ok) setSpooferStatus(await res.json());
    } catch (e) {
      console.error('fetch status failed:', e);
    }
  }, []);

  const fetchStats = useCallback(async () => {
    try {
      const res = await fetch(`${API}/api/stats`);
      if (res.ok) setStats(await res.json());
    } catch (e) {
      console.error('fetch stats failed:', e);
    }
  }, []);

  const addTarget = async (ip: string) => {
    try {
      const res = await fetch(`${API}/api/targets`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip }),
      });
      if (res.ok) {
        await fetchStatus();
      }
    } catch (e) {
      console.error('add target failed:', e);
    }
  };

  const removeTarget = async (ip: string) => {
    try {
      await fetch(`${API}/api/targets/${ip}`, { method: 'DELETE' });
      await fetchStatus();
    } catch (e) {
      console.error('remove target failed:', e);
    }
  };

  const startSpoofer = async () => {
    try {
      const res = await fetch(`${API}/api/spoofer/start`, { method: 'POST' });
      if (res.ok) await fetchStatus();
    } catch (e) {
      console.error('start spoofer failed:', e);
    }
  };

  const stopSpoofer = async () => {
    try {
      const res = await fetch(`${API}/api/spoofer/stop`, { method: 'POST' });
      if (res.ok) await fetchStatus();
    } catch (e) {
      console.error('stop spoofer failed:', e);
    }
  };

  const blockDevice = async (ip: string) => {
    try {
      await fetch(`${API}/api/device/${ip}/block`, { method: 'POST' });
      await fetchStats();
    } catch (e) {
      console.error('block failed:', e);
    }
  };

  const unblockDevice = async (ip: string) => {
    try {
      await fetch(`${API}/api/device/${ip}/unblock`, { method: 'POST' });
      await fetchStats();
    } catch (e) {
      console.error('unblock failed:', e);
    }
  };

  const limitDevice = async (ip: string) => {
    const limit = parseInt(limitInput[ip] || '1000');
    try {
      await fetch(`${API}/api/device/${ip}/limit`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ limit_kbps: limit }),
      });
      await fetchStats();
    } catch (e) {
      console.error('limit failed:', e);
    }
  };

  const unlimitDevice = async (ip: string) => {
    try {
      await fetch(`${API}/api/device/${ip}/unlimit`, { method: 'POST' });
      await fetchStats();
    } catch (e) {
      console.error('unlimit failed:', e);
    }
  };

  useEffect(() => {
    fetchNetworkInfo();
    fetchStatus();
  }, [fetchNetworkInfo, fetchStatus]);

  useEffect(() => {
    if (spooferStatus.running) {
      const interval = setInterval(fetchStats, 1000);
      return () => clearInterval(interval);
    }
  }, [spooferStatus.running, fetchStats]);

  const isTarget = (ip: string) => spooferStatus.targets.includes(ip);
  const getDeviceStats = (ip: string) => stats.find((s) => s.ip === ip);

  return (
    <main className="min-h-screen p-8 max-w-5xl mx-auto">
      <h1 className="text-2xl font-mono mb-6">netcut</h1>

      {/* Network Info */}
      {networkInfo && (
        <div className="mb-8 p-4 border border-neutral-800 rounded font-mono text-sm">
          <div className="grid grid-cols-2 gap-2">
            <span className="text-neutral-500">interface</span>
            <span>{networkInfo.interface}</span>
            <span className="text-neutral-500">ip</span>
            <span>{networkInfo.ip}</span>
            <span className="text-neutral-500">gateway</span>
            <span>{networkInfo.gateway_ip}</span>
            <span className="text-neutral-500">network</span>
            <span>{networkInfo.network}</span>
          </div>
        </div>
      )}

      {/* Controls */}
      <div className="flex gap-4 mb-8">
        <button
          onClick={scanNetwork}
          disabled={loading}
          className="px-4 py-2 bg-neutral-800 hover:bg-neutral-700 rounded font-mono text-sm disabled:opacity-50"
        >
          {loading ? 'scanning...' : 'scan network'}
        </button>

        {spooferStatus.target_count > 0 && (
          <>
            {spooferStatus.running ? (
              <button
                onClick={stopSpoofer}
                className="px-4 py-2 bg-red-900 hover:bg-red-800 rounded font-mono text-sm"
              >
                stop
              </button>
            ) : (
              <button
                onClick={startSpoofer}
                className="px-4 py-2 bg-green-900 hover:bg-green-800 rounded font-mono text-sm"
              >
                start
              </button>
            )}
          </>
        )}

        {spooferStatus.running && (
          <span className="px-3 py-2 text-green-500 font-mono text-sm">
            active ({spooferStatus.target_count} targets)
          </span>
        )}
      </div>

      {error && (
        <div className="mb-4 p-3 bg-red-900/30 border border-red-800 rounded text-red-400 font-mono text-sm">
          {error}
        </div>
      )}

      {/* Device List */}
      {devices.length > 0 && (
        <div className="border border-neutral-800 rounded overflow-hidden">
          <table className="w-full font-mono text-sm">
            <thead className="bg-neutral-900">
              <tr>
                <th className="text-left p-3 text-neutral-500">ip</th>
                <th className="text-left p-3 text-neutral-500">mac</th>
                <th className="text-left p-3 text-neutral-500">hostname</th>
                <th className="text-left p-3 text-neutral-500">status</th>
                <th className="text-right p-3 text-neutral-500">actions</th>
              </tr>
            </thead>
            <tbody>
              {devices.map((device) => {
                const targeted = isTarget(device.ip);
                const deviceStats = getDeviceStats(device.ip);

                return (
                  <tr
                    key={device.ip}
                    className="border-t border-neutral-800 hover:bg-neutral-900/50"
                  >
                    <td className="p-3">
                      {device.ip}
                      {device.is_gateway && (
                        <span className="ml-2 text-neutral-500">(gateway)</span>
                      )}
                    </td>
                    <td className="p-3 text-neutral-400">{device.mac}</td>
                    <td className="p-3 text-neutral-400">
                      {device.hostname || '-'}
                    </td>
                    <td className="p-3">
                      {deviceStats ? (
                        <div>
                          <span
                            className={
                              deviceStats.status === 'blocked'
                                ? 'text-red-400'
                                : deviceStats.status === 'limited'
                                ? 'text-yellow-400'
                                : 'text-green-400'
                            }
                          >
                            {deviceStats.status}
                          </span>
                          {spooferStatus.running && (
                            <div className="text-neutral-500 text-xs mt-1">
                              {deviceStats.download_rate_mbps.toFixed(2)} /{' '}
                              {deviceStats.upload_rate_mbps.toFixed(2)} Mbps
                            </div>
                          )}
                        </div>
                      ) : targeted ? (
                        <span className="text-neutral-500">targeted</span>
                      ) : (
                        '-'
                      )}
                    </td>
                    <td className="p-3 text-right">
                      {!device.is_gateway && (
                        <div className="flex gap-2 justify-end">
                          {!targeted ? (
                            <button
                              onClick={() => addTarget(device.ip)}
                              className="px-2 py-1 text-xs bg-neutral-800 hover:bg-neutral-700 rounded"
                            >
                              target
                            </button>
                          ) : (
                            <>
                              <button
                                onClick={() => removeTarget(device.ip)}
                                className="px-2 py-1 text-xs bg-neutral-800 hover:bg-neutral-700 rounded"
                              >
                                remove
                              </button>
                              {spooferStatus.running && (
                                <>
                                  {deviceStats?.status === 'blocked' ? (
                                    <button
                                      onClick={() => unblockDevice(device.ip)}
                                      className="px-2 py-1 text-xs bg-green-900 hover:bg-green-800 rounded"
                                    >
                                      unblock
                                    </button>
                                  ) : (
                                    <button
                                      onClick={() => blockDevice(device.ip)}
                                      className="px-2 py-1 text-xs bg-red-900 hover:bg-red-800 rounded"
                                    >
                                      block
                                    </button>
                                  )}
                                  {deviceStats?.status === 'limited' ? (
                                    <button
                                      onClick={() => unlimitDevice(device.ip)}
                                      className="px-2 py-1 text-xs bg-green-900 hover:bg-green-800 rounded"
                                    >
                                      unlimit
                                    </button>
                                  ) : (
                                    <div className="flex gap-1">
                                      <input
                                        type="number"
                                        placeholder="kbps"
                                        value={limitInput[device.ip] || ''}
                                        onChange={(e) =>
                                          setLimitInput({
                                            ...limitInput,
                                            [device.ip]: e.target.value,
                                          })
                                        }
                                        className="w-20 px-2 py-1 text-xs bg-neutral-900 border border-neutral-700 rounded"
                                      />
                                      <button
                                        onClick={() => limitDevice(device.ip)}
                                        className="px-2 py-1 text-xs bg-yellow-900 hover:bg-yellow-800 rounded"
                                      >
                                        limit
                                      </button>
                                    </div>
                                  )}
                                </>
                              )}
                            </>
                          )}
                        </div>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {devices.length === 0 && !loading && (
        <p className="text-neutral-500 font-mono text-sm">
          click scan to discover devices on your network
        </p>
      )}
    </main>
  );
}
