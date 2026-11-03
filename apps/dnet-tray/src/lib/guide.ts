/**
 * The setup guide: what the person is told to do, in order, on a provider's own pages and on their own
 * server (design brief 2026-10-30). Plain data and a few pure helpers, so the content is checked by tests and
 * the window only draws it.
 *
 * Rules the content keeps (Principle VI, honest capability claims):
 * - **Only what was checked is stated as fact.** Each provider fact carries the date it was checked and the
 *   provider's own page. Button and menu names that could not be checked against the provider's live pages
 *   are described by what they do, and every guide says the wording may differ.
 * - **No cloud credential is ever asked for.** The person works in the provider's pages themselves. What
 *   comes back to this program is what their own server printed.
 * - **Nothing here claims the connection cannot be seen.** A tunnel is a tunnel (FR-033).
 */

export type GuideId = 'oracle' | 'other';

export interface Fact {
  text: string;
  /** `YYYY-MM-DD`. */
  checked: string;
  /** The provider's own documentation page the fact was read on, as text to read (no scheme). */
  source: string;
}

export type StepAction = 'kind' | 'ports' | 'run' | 'paste' | 'done';

export interface Step {
  id: string;
  title: string;
  /** What the person does, one line each, in order. */
  do: string[];
  /** What they should see when it worked. */
  see?: string;
  /** What to do if it did not. */
  stuck?: string[];
  /** A part of this step that the window itself carries out (a choice, a table, a box to paste into). */
  action?: StepAction;
}

export interface Guide {
  id: GuideId;
  name: string;
  summary: string;
  facts: Fact[];
  steps: Step[];
}

export interface Option {
  id: 'server' | 'local';
  title: string;
  recommended: boolean;
  /** Whether it works in this build. An option that does not is shown, and says so. */
  available: boolean;
  summary: string;
  pros: string[];
  cons: string[];
  features: { text: string; included: boolean }[];
}

/** The two ways to use the program, side by side (design brief 2026-10-30). */
export const OPTIONS: Option[] = [
  {
    id: 'server',
    title: 'Your own server',
    recommended: true,
    available: true,
    summary: 'A small server of yours, in a country you choose, that your traffic goes through.',
    pros: [
      'Keeps working when a network blocks or slows websites and apps.',
      'Tries three different connection methods and uses the one that works where you are.',
      'Moves to another path by itself when Wi-Fi drops, and puts your network back as it was when it stops.',
    ],
    cons: [
      'You set it up once, about 20 minutes, following the steps in this window.',
      'A free server needs an account with a card check at the provider. The card is not charged for the free server.',
      'Free servers have limits, and the provider can change them.',
    ],
    features: [
      { text: 'Get through networks that block sites and apps', included: true },
      { text: 'Switch between Wi-Fi, cable and phone hotspot without dropping', included: true },
      { text: 'Help with Wi-Fi sign-in pages', included: true },
      { text: 'Restore your network exactly as it was after a crash or uninstall', included: true },
      { text: 'Choose which sites and programs go through the server', included: true },
    ],
  },
  {
    id: 'local',
    title: 'Without a server',
    recommended: false,
    available: false,
    summary: 'Only this computer. Nothing to set up, nothing outside it.',
    pros: ['Nothing to create or pay for.', 'Nothing leaves your computer except your normal traffic.'],
    cons: [
      'It cannot get past a network that blocks websites or apps: there is nowhere else for your traffic to go.',
      'Not available in this version yet.',
    ],
    features: [
      { text: 'Switch between Wi-Fi, cable and phone hotspot without dropping', included: true },
      { text: 'Help with Wi-Fi sign-in pages', included: true },
      { text: 'Restore your network exactly as it was after a crash or uninstall', included: true },
      { text: 'Get through networks that block sites and apps', included: false },
      { text: 'Choose which sites and programs go through a server', included: false },
    ],
  },
];

// Shown as text, without a scheme: the window opens no address itself (R4).
const ORACLE_FREE = 'docs.oracle.com/en-us/iaas/Content/FreeTier/freetier.htm';
const ORACLE_ALWAYS_FREE = 'docs.oracle.com/en-us/iaas/Content/FreeTier/resourceref.htm';

const WORDING =
  'The provider changes its pages from time to time. If a button or menu is worded a little differently, choose the one that means the same.';

const OPEN_PORTS: Step = {
  id: 'ports',
  title: 'Open three ports',
  action: 'ports',
  do: [
    'A port is a door into your server. The program needs exactly these three open, and nothing else.',
    'In your provider’s page for the server, find its network firewall rules (the rules for traffic coming in).',
    'Add one rule for each row below: where from is everywhere, the protocol and port are as listed.',
  ],
  see: 'Three new rules in the list, one for each row.',
  stuck: [
    'If the provider has a second place with firewall rules for the server itself, add the same three there too.',
    WORDING,
  ],
};

const RUN: Step = {
  id: 'run',
  title: 'Run the setup on your server',
  action: 'run',
  do: [
    'Open a terminal on your computer: press the Windows key, type PowerShell, press Enter.',
    'Connect to your server with the command below. It uses the key file you saved when you created the server.',
    'When you see a prompt like ubuntu@something:~$, paste the long block below the command and press Enter.',
    'It takes one to three minutes. When it finishes it prints one long line that starts with DNET-BOOTSTRAP-REPORT.',
  ],
  see: 'A line starting with DNET-BOOTSTRAP-REPORT at the end.',
  stuck: [
    'If ssh says UNPROTECTED PRIVATE KEY FILE, run the permission fix shown below the command, then try again.',
    'If it says this server has a different processor, go back and choose the other kind of server.',
    'If it stops with a message about a checksum, do not use that server: start again and tell us.',
  ],
};

const PASTE: Step = {
  id: 'paste',
  title: 'Bring the result back',
  action: 'paste',
  do: [
    'Select the long DNET-BOOTSTRAP-REPORT line in the terminal and copy it. You can also copy a few lines around it.',
    'Paste it in the box below, give the server a name, and type its public address.',
    'The program checks that the result belongs to this setup before it adds the server.',
  ],
  see: 'The server appears in your list of servers.',
};

const DONE: Step = {
  id: 'done',
  title: 'Turn it on',
  action: 'done',
  do: ['Your server is added. Turn the connection on from the Status page.'],
};

export const GUIDES: Record<GuideId, Guide> = {
  oracle: {
    id: 'oracle',
    name: 'Oracle Cloud, free',
    summary:
      'The only lasting free server we found. It needs a phone number and a card for identity checks, and it can be short of capacity in a popular region.',
    facts: [
      {
        text: 'Most people need a mobile phone number and a credit card to create the account. The card is not charged unless you upgrade.',
        checked: '2026-10-30',
        source: ORACLE_FREE,
      },
      {
        text: 'Always Free resources keep working after the 30-day trial ends. Free servers can only be created in the home region you choose at sign-up.',
        checked: '2026-10-30',
        source: ORACLE_FREE,
      },
      {
        text: 'Free servers: two small AMD servers (1 GB memory, up to 50 Mbps), or Arm servers totalling 2 cores and 12 GB. 10 TB of outgoing traffic a month.',
        checked: '2026-10-30',
        source: ORACLE_ALWAYS_FREE,
      },
      {
        text: 'A server that stays mostly idle for 7 days can be reclaimed by Oracle. This program keeps its server busy enough to avoid that.',
        checked: '2026-10-30',
        source: ORACLE_ALWAYS_FREE,
      },
    ],
    steps: [
      {
        id: 'before',
        title: 'What you need',
        do: [
          'About 20 minutes, an email address, a mobile phone that can receive a text, and a credit or debit card.',
          'The card is for an identity check. It is not charged for the free server, as long as you do not upgrade the account.',
          'Plan where the server should be: a different country from the network that blocks you, ideally one not far away.',
        ],
        see: 'You have the phone and card at hand.',
        stuck: ['If you cannot use a card, choose “Another server” on the previous screen and use any provider you can pay.'],
      },
      {
        id: 'account',
        title: 'Create your Oracle Cloud account',
        do: [
          'On your computer, open your browser and go to oracle.com/cloud/free.',
          'Choose the button to start for free, and fill in your details. Use your real name and a card in the same name.',
          'When you are asked for a home region, choose carefully: your free server can only be created in that region.',
          'Pick a region in another country from the network that blocks you. A region closer to you is faster.',
        ],
        see: 'An email from Oracle, then the Oracle Cloud Console (a page with a menu at the top left) when you sign in.',
        stuck: ['If the card is refused, try another card.', WORDING],
      },
      {
        id: 'kind',
        title: 'Choose the kind of server',
        action: 'kind',
        do: [
          'Arm is faster and is the better choice. Oracle can run out of Arm servers in a region.',
          'AMD is always there, but it is limited to about 50 Mbps. That is enough for browsing and messages, and slow for video.',
        ],
      },
      {
        id: 'create',
        title: 'Create the server',
        do: [
          'In the Console, open the menu at the top left, then Compute, then Instances, and choose Create instance.',
          'Name: anything you like. Image: choose Ubuntu (the newest long-term version).',
          'Shape: choose the one that matches your choice above. For Arm, 1 core and 6 GB is plenty (the free limit is 2 cores and 12 GB in total).',
          'Networking: keep the defaults and make sure a public IPv4 address will be assigned.',
          'SSH keys: choose to generate a key pair, and download the private key. Keep that file: you need it in a moment.',
          'Choose Create.',
        ],
        see: 'The server’s page, with its state changing from Provisioning to Running, and a Public IP address.',
        stuck: [
          'If it says there is no capacity for the shape, try again in a few hours, or choose the other kind of server.',
          'Write down the public IP address. You need it for the next steps.',
          WORDING,
        ],
      },
      OPEN_PORTS,
      RUN,
      PASTE,
      DONE,
    ],
  },

  other: {
    id: 'other',
    name: 'Another server',
    summary: 'Any Linux server you have or rent: Ubuntu or Debian, with its own public IPv4 address and at least 1 GB of memory.',
    facts: [],
    steps: [
      {
        id: 'before',
        title: 'What you need',
        do: [
          'A Linux server (Ubuntu or Debian) with a public IPv4 address, at least 1 GB of memory, and a user that can run commands as administrator.',
          'The key file or password to connect to it. You will connect from your own computer.',
          'The server should be in another country from the network that blocks you.',
        ],
        see: 'You can log in to the server with ssh from PowerShell.',
        stuck: ['Most rented servers show an address and a user name on their page, and let you download a key.'],
      },
      {
        id: 'kind',
        title: 'Choose the kind of processor',
        action: 'kind',
        do: [
          'Most servers are Intel or AMD. Some are Arm. Your provider’s page for the server says which.',
          'If you are not sure, run uname -m on the server: x86_64 means Intel or AMD, aarch64 means Arm.',
        ],
      },
      OPEN_PORTS,
      RUN,
      PASTE,
      DONE,
    ],
  },
};

/** The most recent date any fact in `guide` was checked. */
export function checkedOn(guide: Guide): string | null {
  const dates = guide.facts.map((f) => f.checked).sort();
  return dates.at(-1) ?? null;
}

export interface PortRow {
  protocol: string;
  port: string;
  /** Where traffic may come from. */
  source: string;
}

/** The rule table the person copies into their provider's firewall. */
export function portRows(ports: { protocol: string; port: number }[]): PortRow[] {
  return ports.map((p) => ({ protocol: p.protocol.toUpperCase(), port: String(p.port), source: '0.0.0.0/0' }));
}

const END_OF_PASTE = 'DNET_SETUP_EOF';

/**
 * The block the person pastes into their server's terminal: the script written to a file, then run from the
 * file. Run from the terminal's own input, a command that reads input could swallow the rest of the script.
 * Refuses a script that holds the end marker on a line of its own, which would end the paste early.
 */
export function wrapForPaste(script: string): string {
  if (script.split('\n').some((line) => line.trim() === END_OF_PASTE)) {
    throw new Error('the script contains the end marker');
  }
  const body = script.endsWith('\n') ? script : `${script}\n`;
  return `cat > dnet-setup.sh <<'${END_OF_PASTE}'\n${body}${END_OF_PASTE}\nsudo sh dnet-setup.sh`;
}

/** Whether `text` could be a server's address: an IPv4 address or a host name, and nothing else. */
export function isPlausibleAddress(text: string): boolean {
  if (text.length === 0 || text.length > 253) return false;
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(text);
  if (v4) return v4.slice(1).every((part) => Number(part) <= 255);
  return /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(text);
}

/**
 * The command that connects to the server, built only from parts that are what they should be. A part that
 * is not is shown as a placeholder in angle brackets, so what is copied can never carry shell syntax.
 */
export function sshCommand(address: string, user: string, keyFile: string): string {
  const safeUser = /^[a-z_][a-z0-9_-]{0,31}$/i.test(user) ? user : '<user name>';
  const safeKey = /^[^"`$;&|<>\r\n]{1,260}$/.test(keyFile) ? keyFile : '<key file>';
  const safeAddress = isPlausibleAddress(address) ? address : '<server address>';
  return `ssh -i "${safeKey}" ${safeUser}@${safeAddress}`;
}

/** The fix for ssh refusing a key file that other accounts on this computer can read. */
export function keyPermissionFix(keyFile: string): string {
  const safeKey = /^[^"`$;&|<>\r\n%]{1,260}$/.test(keyFile) ? keyFile : '<key file>';
  return `icacls "${safeKey}" /inheritance:r /grant:r "%USERNAME%:R"`;
}
