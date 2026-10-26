/**
 * Every sentence the window says, in one place, with named placeholders (design-system §16: no sentence is a
 * concatenation, so a translation can reorder). English only in v1; the door is kept open.
 *
 * Voice (§14): plain, active, present tense, concrete numbers; says what changed and why. Never "Oops", an
 * exclamation mark, or "protected / secure / private / anonymous" (ADR-0006 §3). Protocol names as named;
 * the third-party components are named only in About (`lint-branding`).
 *
 * The one place that must agree with the service word for word is the encrypted-DNS disclosure, which is
 * `disclosure.json`, checked against `dnet_core::doh_consent::disclosure()` by a Rust test.
 */
import disclosure from './disclosure.json';
// The words the tray menu shares with the window: one file, built into both (crates/dnet-view/words.json).
import words from '../../../../crates/dnet-view/words.json';

export { disclosure, words };

export const en = {
  state: {
    off: words.off,
    probe: words.probe,
    ok: words.ok,
    warn: words.warn,
  },
  because: {
    off: 'Your traffic is leaving this computer directly. Nothing is being changed.',
    probe: 'Testing the connection methods on this network.',
    ok: 'Carrying your traffic over {network} through {endpoint}, using {method}.',
    okNoNetwork: 'Carrying your traffic through {endpoint}, using {method}.',
    warn: '{network} is slow or dropping packets.',
    warnOnlyPath: '{network} is slow or dropping packets, and it is the only network available, so there is nothing to switch to.',
    warnNoBetter: '{network} is slow or dropping packets, and no other network is better right now.',
    warnProving: 'A better network was found and is being checked before the connection moves to it.',
    warnDwell: 'The connection moved recently, so it will not move again yet.',
    warnBudget: 'The connection has moved several times lately, so it is staying put for now.',
  },
  switch: { off: words.stabilize, busy: words.working, on: 'Stabilized', label: 'Stabilize this connection', turnOff: words.turnOff },
  facts: { tier1: 'Tier 1', tier2: 'Tier 2', line: '{method} · {tier}', via: '{method} · {tier} · via {network}' },
  method: { AmneziaWg: 'AmneziaWG', Hysteria2: 'Hysteria 2', VlessReality: 'VLESS + REALITY' },
  network: {
    Wifi: 'Wi-Fi',
    Cellular: 'Mobile',
    Ethernet: 'Cable',
    Other: 'Network',
  },
  role: {
    Carrying: 'Carrying',
    Standby: 'Standby · ready',
    Available: 'Available',
    Unusable: 'Unavailable',
  },
  metrics: { measured: '{rtt} ms · {loss} % loss', notMeasured: 'not measured', unavailable: 'not available' },
  heartbeat: { live: 'Live · updated {seconds} s ago', stale: 'Last update {seconds} s ago', none: 'Waiting for the service' },
  notices: {
    Tier2ProfileActive: 'This connection method drops established connections when your network changes.',
    BrutalEnabled: 'Faster-but-aggressive mode is on. It makes the Wi-Fi worse for everyone around you.',
    EncryptedDnsOverridden: 'Your browser’s own encrypted name lookups are blocked so that your rules apply.',
  },
  instruments: {
    latency: 'Latency',
    jitter: 'Jitter',
    loss: 'Loss',
    stability: 'Stability',
    none: 'no measurement',
    notWatching: 'nothing is being measured',
    ping: 'also called ping',
    typical: 'usually {low}–{high} ms',
    steady: 'steady',
    poorSpells: { zero: '0 poor spells', one: '1 poor spell', other: '{count} poor spells' },
    session: '{duration} · {changes}',
    changes: { zero: 'no network changes', one: '1 network change', other: '{count} network changes' },
    details: 'Details',
  },
  drawer: {
    networks: 'Your networks',
    since: 'This connection',
    columns: { network: 'Network', role: 'Role', latency: 'Latency', jitter: 'Jitter', loss: 'Loss' },
    connectedFor: 'Connected for',
    networkChanges: 'Network changes',
    dropping: '…under a Tier 2 method (breaks connections)',
    methodSwitches: 'Method switches',
    endpointSwitches: 'Endpoint switches',
    poorSpells: 'Poor spells',
    longestPoor: 'Longest poor spell',
    fine: 'Counted on this computer. Nothing here compares with not using DNet Engine; a comparison would be a measurement you start, labelled with its time and method.',
    notWatching: 'Networks are listed while a connection is up.',
  },
  nav: { status: 'Status', endpoints: 'Endpoints', rules: 'Rules', activity: 'Activity', settings: 'Settings', sections: 'Sections', about: 'About DNet Engine' },
  actions: {
    openLogin: 'Open login page',
    checkEndpoints: 'Check endpoints',
    retry: 'Retry',
    viewDiagnostics: 'View diagnostics',
    showAdapters: 'Show network details',
    grantRights: 'How to grant them',
  },
  help: {
    grantRights:
      'The background service needs to run as the system or as an administrator. If you started it yourself, start it again from an administrator prompt.',
  },
  concept: 'Concept · using several networks at once is not in v1',
  scene: { label: 'Your networks' },
  consent: {
    tier2: {
      title: 'This method will drop your connections when the network changes',
      body: 'This is the best way through on this network right now, but it has not been shown to keep a download alive when you move from one network to another.',
      consequence: 'Your downloads and calls will drop when you switch networks.',
      note: 'A method that survives a switch is not available on this network.',
      decline: 'Don’t connect',
      accept: 'Connect anyway',
    },
    brutal: {
      title: 'Turn on aggressive speed mode?',
      body: 'This mode sends as fast as it can instead of backing off when the network is busy.',
      consequence: 'This makes the Wi-Fi worse for everyone around you, including you.',
      note: 'You tell the mode how fast your connection is. If that figure is too high, it will make things worse.',
      decline: 'Keep it off',
      accept: 'Turn it on',
    },
    dns: {
      title: 'Turn off the encrypted name lookup block?',
      // The consequence is `disclosure.consequenceOfOptingOut`: the service's own words.
      decline: 'Keep blocking',
      accept: 'Turn it off',
      on: 'Block programs’ own encrypted name lookups',
      onHelp: 'On (the default): your rules for sites and domains apply to programs such as your browser.',
      offHelp: 'Off: programs keep using their own encrypted lookups, and site rules do not apply to them.',
    },
    acceptableUse: {
      title: 'Before you connect on a managed network',
      body: 'Using this on a network you do not own may break that network’s rules, such as a school’s or an employer’s acceptable-use policy.',
      consequence: 'If it does, the consequences are yours. This program does not hide that a tunnel exists, and it does not hide how much traffic you send or where it goes.',
      note: 'Read the policy of the network you are on. This program is for staying connected on networks you do not control, not for avoiding rules you have agreed to.',
      decline: 'Not now',
      accept: 'I understand',
    },
  },
  views: {
    endpoints: {
      title: 'Endpoints',
      empty: 'No endpoints yet. An endpoint is a server you control, and the place your traffic leaves from.',
      add: 'Add a server you already have',
      setup: 'Set one up for me',
      enabled: 'In use',
      disabled: 'Not in use',
      remove: 'Remove',
      enable: 'Use',
      disable: 'Don’t use',
      removeTitle: 'Remove this endpoint?',
      removeBody: 'Its saved connection details are deleted from this computer. The server itself is not touched.',
      removeAccept: 'Remove it',
      removeDecline: 'Keep it',
      health: { Unknown: 'Not checked', Healthy: 'Answering', Degraded: 'Slow', Unreachable: 'Not answering' },
      changeNeedsDisconnect: 'Disconnect to change endpoints.',
      form: {
        label: 'Name',
        labelHelp: 'Letters, numbers and spaces; shown in the window.',
        host: 'Address',
        hostHelp: 'The server’s IP address or host name.',
        credentials: 'Connection details',
        credentialsHelp: 'The connection file for this server. It holds keys, so delete the file afterwards.',
        choose: 'Choose a file…',
        submit: 'Add endpoint',
        cancel: 'Cancel',
      },
    },
    rules: {
      title: 'Rules',
      empty: 'No rules of your own yet. Built-in rules keep your local network and sign-in pages working.',
      builtin: 'Built in · cannot be removed',
      reliable: 'Reliable',
      bestEffort: 'Best effort',
      bestEffortNote: 'Rules by program are best effort: a program can slip past one. Rules by address and by domain are reliable.',
      precedence: 'Order',
      action: 'Action',
      kind: 'How sure',
      origin: 'Origin',
      explainer: 'Rules are checked in this order, strongest first. The built-in ones always win, so you cannot lock yourself out of your own network.',
    },
    activity: {
      title: 'Activity',
      empty: 'Nothing has happened yet in this session. What the program does, and why, will appear here.',
      note: 'Every automatic change is listed with its reason.',
    },
    settings: {
      title: 'Settings',
      theme: 'Appearance',
      themeSystem: 'Follow the system',
      themeDark: 'Dark',
      themeLight: 'Light',
      motion: 'Reduce motion',
      motionHelp: 'Stops the figure turning. The words still say what is happening.',
      updates: 'Connection method updates',
      updatesHelp: 'Checks for updated settings for the connection methods. It goes through your connection when one is up, and directly over your network only when you press the button while disconnected.',
      checkNow: 'Check now',
      checking: 'Checking…',
      checkedTunnel: 'Checking through your connection. The result shows in Activity.',
      checkedPhysical: 'Checking directly over your network, because you asked while disconnected. The result shows in Activity.',
      about: 'About',
    },
    about: {
      title: 'About DNet Engine',
      body: 'DNet Engine helps keep a connection going on networks that interfere with it. It is free software, licensed under the GNU General Public License, version 3.',
      attribution: 'It uses these components, under their own licences:',
      close: 'Close',
    },
  },
  firstRun: {
    welcome: 'Welcome',
    haveServer: 'Do you already have a server?',
    yes: 'Yes, I have one',
    no: 'No, set one up for me',
    next: 'Continue',
    back: 'Back',
    dnsTitle: 'About encrypted name lookups',
    intro: 'DNet Engine keeps your connection going on networks that interfere with it. Two things to know before you start.',
    endpointNote: 'It needs a server of yours to send traffic through. You can add one you already have, or have one set up in your own cloud account. The program runs none for you.',
    finish: 'Get started',
  },
  wizard: {
    title: 'Set up a server',
    unavailable: 'Setting up a server is not available in this build yet.',
    body: 'This will create a small server in your own cloud account, install the connection software on it, and check that it works. You can remove it afterwards from here.',
    stepOf: 'Step {n} of {total}: {name}',
    close: 'Close',
    steps: ['What this needs', 'Your cloud account', 'Choose a place', 'Setting up', 'Preparing the server', 'Checking it works', 'Clean up'],
  },
  switcher: { label: 'Go to…', placeholder: 'Type a command', none: 'Nothing matches' },
  errors: {
    service: words.serviceDown,
    refused: 'The service refused: {reason}',
    disconnectFirst: 'Disconnect before changing endpoints or encrypted-name settings.',
  },
} as const;

/** Fill `{name}` placeholders. A placeholder with no value is left visible, so the gap shows up in review. */
export function fill(template: string, values: Record<string, string | number>): string {
  return template.replace(/\{(\w+)\}/g, (whole, key: string) => {
    const value = values[key];
    return value === undefined ? whole : String(value);
  });
}

/** The right form of a counted phrase. */
export function plural(forms: { zero: string; one: string; other: string }, count: number): string {
  const template = count === 0 ? forms.zero : count === 1 ? forms.one : forms.other;
  return fill(template, { count });
}
