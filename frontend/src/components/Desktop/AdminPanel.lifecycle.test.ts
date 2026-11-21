import { describe, expect, it } from 'vitest';
import source from './AdminPanel.tsx?raw';

const start = source.slice(
  source.indexOf('const handleStart ='),
  source.indexOf('const handleStop ='),
);
const stop = source.slice(source.indexOf('const handleStop ='), source.indexOf('if (loading)'));

describe('Admin Panel backend lifecycle', () => {
  it('uses the managed Tauri startup path', () => {
    expect(start).toContain("invoke<SetupStatus>('get_setup_status')");
    expect(start).toContain("invoke<void>('start_backend')");
    expect(start).toContain("previous.phase === 'stop_unconfirmed'");
    expect(start).toContain('Managed backend startup requested.');
    expect(source).not.toContain('waitForManagedBackend');
    expect(source).not.toContain('120_000');
    expect(start).not.toContain('run_jarvis_command');
  });

  it('surfaces an unconfirmed managed shutdown and avoids the CLI stop path', () => {
    expect(stop).toContain("invoke<void>('stop_backend')");
    expect(stop).toContain("status?.phase === 'stop_unconfirmed'");
    expect(stop).toContain('Shutdown unconfirmed:');
    expect(stop).not.toContain('run_jarvis_command');
  });
});
