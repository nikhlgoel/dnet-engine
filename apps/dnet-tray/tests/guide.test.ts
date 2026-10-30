import { describe, expect, it } from 'vitest';
import {
  GUIDES,
  OPTIONS,
  checkedOn,
  portRows,
  sshCommand,
  wrapForPaste,
  isPlausibleAddress,
  type GuideId,
} from '../src/lib/guide';

// Assembled, so that this file does not itself trip the branding lint.
const FORBIDDEN = [['sing', 'box'].join('-'), ['sing', 'box'].join(''), ['wire', 'guard'].join(''), ['win', 'tun'].join('')];
const ids = Object.keys(GUIDES) as GuideId[];

describe('the two choices', () => {
  it('puts the server first, recommended, with pros and cons for both and what the second lacks', () => {
    expect(OPTIONS.map((o) => o.id)).toEqual(['server', 'local']);
    const [server, local] = OPTIONS as [(typeof OPTIONS)[number], (typeof OPTIONS)[number]];
    expect(server.recommended).toBe(true);
    expect(local.recommended).toBe(false);
    for (const o of OPTIONS) {
      expect(o.pros.length).toBeGreaterThan(1);
      expect(o.cons.length).toBeGreaterThan(0);
      expect(o.features.length).toBeGreaterThan(2);
    }
    // The second option is honest about what it cannot do: it cannot get past a network that blocks.
    const missing = local.features.filter((f) => !f.included).map((f) => f.text.toLowerCase());
    expect(missing.some((t) => t.includes('block'))).toBe(true);
    // And it is not offered as working until it is.
    expect(local.available).toBe(false);
    expect(server.available).toBe(true);
  });
});

describe('each guide', () => {
  for (const id of ids) {
    const guide = GUIDES[id];

    it(`${id}: every step says where to go, what to do, and what you should then see`, () => {
      expect(guide.steps.length).toBeGreaterThanOrEqual(6);
      const seen = new Set<string>();
      for (const step of guide.steps) {
        expect(seen.has(step.id), `duplicate step ${step.id}`).toBe(false);
        seen.add(step.id);
        expect(step.title.length).toBeGreaterThan(3);
        expect(step.do.length, step.id).toBeGreaterThan(0);
        for (const line of step.do) expect(line.trim().length).toBeGreaterThan(5);
        // The two kinds of step the person acts on in the window have nothing to look for elsewhere.
        if (!step.action) expect(step.see, `${step.id} has no "you should see"`).toBeTruthy();
      }
    });

    it(`${id}: ends by getting the result back and turning it on, in that order`, () => {
      const order = guide.steps.map((s) => s.action ?? s.id);
      expect(order.indexOf('run')).toBeGreaterThan(-1);
      expect(order.indexOf('paste')).toBeGreaterThan(order.indexOf('run'));
      expect(order.at(-1)).toBe('done');
    });

    it(`${id}: uses no name the product may not use, and no instruction to hide that it is a tunnel`, () => {
      const text = JSON.stringify(guide).toLowerCase();
      for (const word of FORBIDDEN) expect(text).not.toContain(word);
      expect(text).not.toContain('undetectable');
      expect(text).not.toContain('bypass the school');
    });

    it(`${id}: no step is longer than a person can read at a glance`, () => {
      for (const step of guide.steps) {
        for (const line of [...step.do, ...(step.stuck ?? []), step.see ?? '']) {
          expect(line.length, `${step.id}: ${line.slice(0, 40)}`).toBeLessThan(420);
        }
      }
    });
  }

  it('the free provider says what the free server costs: a card check, a region choice, a speed cap, reclaiming', () => {
    const text = JSON.stringify(GUIDES.oracle).toLowerCase();
    for (const must of ['credit card', 'not charged', 'home region', '50 mbps', 'reclaim']) {
      expect(text, must).toContain(must);
    }
  });

  it('every claim about a provider carries the date it was checked and where', () => {
    for (const fact of GUIDES.oracle.facts) {
      expect(fact.text.length).toBeGreaterThan(10);
      expect(fact.checked).toMatch(/^\d{4}-\d{2}-\d{2}$/);
      expect(fact.source).toMatch(/^docs\./);
    }
    expect(checkedOn(GUIDES.oracle)).toBe('2026-10-30');
  });
});

describe('what the window builds for the person to paste', () => {
  const ports = [
    { protocol: 'udp', port: 51820 },
    { protocol: 'udp', port: 44443 },
    { protocol: 'tcp', port: 8443 },
  ];

  it('lists each port as protocol, number and where traffic may come from', () => {
    expect(portRows(ports)).toEqual([
      { protocol: 'UDP', port: '51820', source: '0.0.0.0/0' },
      { protocol: 'UDP', port: '44443', source: '0.0.0.0/0' },
      { protocol: 'TCP', port: '8443', source: '0.0.0.0/0' },
    ]);
  });

  it('writes the script to a file and runs it from the file, not from the terminal input', () => {
    const wrapped = wrapForPaste('#!/bin/sh\necho hi\n');
    const lines = wrapped.split('\n');
    expect(lines[0]).toBe("cat > dnet-setup.sh <<'DNET_SETUP_EOF'");
    expect(lines).toContain('DNET_SETUP_EOF');
    expect(lines.at(-1)).toBe('sudo sh dnet-setup.sh');
    // The script sits between, untouched.
    expect(wrapped).toContain('#!/bin/sh\necho hi\n');
  });

  it('refuses a script that could end the paste early', () => {
    expect(() => wrapForPaste('echo 1\nDNET_SETUP_EOF\nrm -rf x\n')).toThrow();
    expect(() => wrapForPaste('echo DNET_SETUP_EOF # inside a line is fine')).not.toThrow();
  });

  it('builds the connection command only from an address that could be a server', () => {
    expect(isPlausibleAddress('203.0.113.10')).toBe(true);
    expect(isPlausibleAddress('server.example.com')).toBe(true);
    for (const bad of ['', 'a b', 'x;rm -rf /', '$(id)', '203.0.113.10:22', 'a/b', "x'y", '1.2.3', 'http://x']) {
      expect(isPlausibleAddress(bad), bad).toBe(false);
    }
    expect(sshCommand('203.0.113.10', 'ubuntu', 'C:\\Users\\me\\ssh.key')).toBe(
      'ssh -i "C:\\Users\\me\\ssh.key" ubuntu@203.0.113.10',
    );
    // A bad address or user is shown as a placeholder, never built into a command.
    expect(sshCommand('x;id', 'ubuntu', 'k')).toContain('<server address>');
    expect(sshCommand('203.0.113.10', 'a b', 'k')).toContain('<user name>');
    expect(sshCommand('203.0.113.10', 'ubuntu', 'k"; id; "')).toContain('<key file>');
  });
});
