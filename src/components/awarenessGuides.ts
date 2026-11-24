export interface AwarenessGuide {
  id: string;
  title: string;
  summary: string;
  severity: 'medium' | 'high';
  what: string;
  steps: string[];
  help: Array<{ label: string; url: string }>;
  prevent: string[];
}

export const AWARENESS_GUIDES: AwarenessGuide[] = [
  {
    id: 'phone-email',
    title: 'Phone number or email is public',
    summary: 'Strangers can find your phone number or email online.',
    severity: 'medium',
    what: 'Your contact details appear on a website, a social media profile, or a search result. Scammers and spammers can use them to send fake messages or try to reset your passwords.',
    steps: [
      'Search for your number and email on Google to see where they appear.',
      'Remove them from your own social media profiles, or set them to private.',
      "Ask the website owner to remove them. Use the site's contact or report page.",
      'Turn on two-step login for your email account.',
      'Do not reply to unknown calls or messages. Block and report them.',
    ],
    help: [{ label: 'Google: Results about you', url: 'https://support.google.com/websearch/answer/9673730' }],
    prevent: [
      'Share your contact details only with people you trust.',
      'Use a separate email address for online forms and shops.',
      'Check your privacy settings every few months.',
    ],
  },
  {
    id: 'address-location',
    title: 'Home address or location is public',
    summary: 'People can see where you live, study, or spend time.',
    severity: 'high',
    what: 'Your address or live location can be found in posts, photos, tags, or public records. This can put your safety at risk, including stalking and theft.',
    steps: [
      'Delete or hide posts that show your home, school, or daily routine.',
      'Turn off location tags in your camera and social media apps.',
      'Set your profiles to private and check who can see your old posts.',
      'Ask websites to remove your address.',
      'If you feel unsafe, tell a trusted person and contact local authorities.',
    ],
    help: [{ label: 'Google: Results about you', url: 'https://support.google.com/websearch/answer/9673730' }],
    prevent: [
      'Post trips after you come back, not while you are away.',
      'Check photos for street signs, house numbers, and uniforms before you post.',
      'Do not share live location with people you do not know well.',
    ],
  },
  {
    id: 'fake-profile',
    title: 'Fake profile or impersonation',
    summary: 'Someone is pretending to be you online.',
    severity: 'high',
    what: 'Another person uses your name, photos, or details to make a fake account. They may try to trick your friends, ask for money, or damage your name.',
    steps: [
      'Take screenshots of the fake profile. Save the link too.',
      'Report the profile with the platform’s impersonation report tool.',
      'Tell your friends and family not to trust the fake account.',
      'Post a short warning on your real profile.',
      'If the person asks for money or threatens you, report it to the police.',
    ],
    help: [
      { label: 'Facebook: report impersonation', url: 'https://www.facebook.com/help/174210519303259' },
      { label: 'Instagram: report impersonation', url: 'https://help.instagram.com/446663175382270' },
    ],
    prevent: [
      'Make your photos and friend list visible only to friends.',
      'Search your own name every few months.',
      'Use a profile frame or watermark on your main photos.',
    ],
  },
  {
    id: 'hacked-account',
    title: 'Leaked password or hacked account',
    summary: 'Your password was found in a data leak, or someone used your account.',
    severity: 'high',
    what: 'A website you used was hacked, or someone guessed your password. They can read your messages, post as you, and try the same password on other accounts.',
    steps: [
      'Change the password now. Use a new, long password that you have never used before.',
      'Change the password on any other site that used the same password.',
      'Turn on two-step login.',
      'Log out of all devices and check the list of devices that are logged in.',
      'Check your email forwarding rules and recovery phone number. Remove anything you do not know.',
      'Warn your contacts if the account sent strange messages.',
    ],
    help: [{ label: 'Have I Been Pwned: check your email', url: 'https://haveibeenpwned.com' }],
    prevent: [
      'Use a different password for each important account.',
      'Use a password manager.',
      'Never share one-time codes (OTP) with anyone.',
    ],
  },
  {
    id: 'private-content',
    title: 'Private photos or data shared without permission',
    summary: 'Someone posted or sent your private photos, videos, or documents.',
    severity: 'high',
    what: 'Private content about you is online without your permission. This is not your fault. The person who shared it is responsible.',
    steps: [
      'Do not reply to the person or pay them. Stay calm.',
      'Save proof: screenshots, links, dates, and usernames.',
      'Report the content on the platform. Most platforms have a reporting process.',
      'Ask a trusted person to support you.',
      'Report threats or serious abuse to the appropriate authorities.',
    ],
    help: [{ label: 'StopNCII.org: stop private images from spreading', url: 'https://stopncii.org' }],
    prevent: [
      'Think carefully before you send private photos to anyone.',
      'Turn off automatic cloud backup for private folders.',
      'Use strong screen locks on your phone.',
    ],
  },
  {
    id: 'scam-harassment',
    title: 'Scam or harassment messages',
    summary: 'You get threats, fake offers, or unwanted messages.',
    severity: 'medium',
    what: 'Scammers use the information they found about you to make messages look real. Some people also use it to bully or frighten you.',
    steps: [
      'Do not click links or open files in the message.',
      'Do not send money, codes, or personal details.',
      'Block the sender and report the account.',
      'Save screenshots as proof before you delete anything.',
      'If you lost money, contact your bank or mobile wallet service right away.',
      'If you are threatened, tell someone you trust and contact the appropriate authorities.',
    ],
    help: [{ label: 'Contact your local police or cybercrime unit', url: '' }],
    prevent: [
      'Be careful with messages that make you feel afraid or in a hurry.',
      'Check offers on the company’s official website.',
      'Keep your social media profiles private.',
    ],
  },
];
