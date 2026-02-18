/*
 * YARA Rules for Supply Chain & Agent Skill Malware Detection
 * repo-analyzer v1.2
 * 
 * Sources: Unit42 AMOS research, tgiovanni1 ClawHub findings,
 * ReversingLabs npm supply chain patterns, public malware signatures
 */

rule AMOS_Stealer_Patterns {
    meta:
        description = "Atomic Stealer (AMOS) macOS infostealer patterns"
        author = "repo-analyzer"
        severity = "critical"
        reference = "https://unit42.paloaltonetworks.com/macos-stealers-growing/"
    strings:
        // Chrome credential theft
        $chrome_login = "Library/Application Support/Google/Chrome" ascii nocase
        $chrome_cookies = "Chrome/Default/Cookies" ascii nocase
        $chrome_login_data = "Login Data" ascii
        // Firefox credential theft
        $firefox_profiles = "Library/Application Support/Firefox/Profiles" ascii nocase
        // Keychain access
        $keychain = "security find-generic-password" ascii
        $keychain2 = "security find-internet-password" ascii
        $keychain_dump = "security dump-keychain" ascii
        // Crypto wallet theft
        $metamask = "Library/Application Support/Google/Chrome/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn" ascii
        $phantom_wallet = "Library/Application Support/Google/Chrome/Default/Local Extension Settings/bfnaelmomeimhlpmgjnjophhpkkoljpa" ascii
        $exodus = "Library/Application Support/Exodus" ascii
        // AppleScript social engineering
        $applescript_dialog = "display dialog" ascii
        $applescript_password = "with hidden answer" ascii
    condition:
        // Need credential theft + exfil indicators
        (any of ($chrome_*, $firefox_*, $keychain*)) and (any of ($metamask, $phantom_wallet, $exodus)) or
        ($applescript_dialog and $applescript_password and any of ($chrome_*, $keychain*))
}

rule Credential_Harvester_Generic {
    meta:
        description = "Generic credential harvesting patterns across platforms"
        author = "repo-analyzer"
        severity = "critical"
    strings:
        // Browser credential paths (cross-platform)
        $chromium_linux = ".config/google-chrome" ascii nocase
        $chromium_win = "AppData/Local/Google/Chrome/User Data" ascii nocase
        $brave_data = "BraveSoftware/Brave-Browser" ascii nocase
        $edge_data = "Microsoft/Edge/User Data" ascii nocase
        // SSH key theft
        $ssh_dir = ".ssh/id_rsa" ascii
        $ssh_dir2 = ".ssh/id_ed25519" ascii
        // AWS/Cloud credential theft
        $aws_creds = ".aws/credentials" ascii
        $gcloud = ".config/gcloud" ascii
        // Env file theft
        $env_steal = /readFile.{0,60}\.env/
        $env_steal2 = /cat\s+.{0,30}\.env/
        // Wallet seed phrases
        $seed_regex = /mnemonic|seed.?phrase|recovery.?phrase|secret.?words/i
        // Password stores
        $pass_store = ".password-store" ascii
        $1password = "1Password" ascii
    condition:
        3 of them
}

rule Reverse_Shell_Script {
    meta:
        description = "Reverse shell establishment patterns"
        author = "repo-analyzer"
        severity = "critical"
    strings:
        $bash_rs = /bash\s+-i\s+>&\s*\/dev\/tcp\// ascii
        $nc_rs = /nc\s+-e\s+\/bin\/(ba)?sh/ ascii
        $python_rs = "socket.socket" ascii
        $python_rs2 = "subprocess.call" ascii
        $python_rs3 = "connect((" ascii
        $perl_rs = /perl\s+-e\s+.{0,60}socket.{0,30}INET/ ascii
        $ruby_rs = /ruby\s+-rsocket/ ascii
        $php_rs = "fsockopen" ascii
        $php_rs2 = "exec(" ascii
        $powershell_rs = "New-Object System.Net.Sockets.TCPClient" ascii
        $ncat_rs = /ncat\s+.{0,40}-e/ ascii
    condition:
        ($bash_rs) or ($nc_rs) or ($perl_rs) or ($ruby_rs) or ($ncat_rs) or
        ($powershell_rs) or
        ($python_rs and $python_rs2 and $python_rs3) or
        ($php_rs and $php_rs2)
}

rule NPM_Supply_Chain_Attack {
    meta:
        description = "npm/node supply chain attack patterns"
        author = "repo-analyzer"
        severity = "critical"
        reference = "https://stairwell.com/resources/how-to-detect-npm-package-manager-supply-chain-attacks-with-yara/"
    strings:
        // Exfiltration via DNS or HTTP in install hooks
        $preinstall = "preinstall" ascii
        $postinstall = "postinstall" ascii
        $install_hook = "\"install\"" ascii
        // Common exfil patterns in npm attacks
        $exfil_dns = "dns.resolve" ascii
        $exfil_webhook = "webhook" ascii nocase
        $exfil_telegram = "api.telegram.org" ascii
        $exfil_discord = "discord.com/api/webhooks" ascii
        $exfil_pastebin = "pastebin.com" ascii
        // Encoded payloads
        $b64_eval = /eval\s*\(\s*Buffer\.from\s*\(/ ascii
        $b64_atob = /eval\s*\(\s*atob\s*\(/ ascii
        $hex_decode = /Buffer\.from\s*\(\s*['"][0-9a-f]{40,}['"]\s*,\s*['"]hex['"]/ ascii
        // Environment variable exfiltration
        $env_steal_node = "process.env" ascii
        $env_keys = /Object\.keys\(process\.env\)/ ascii
        $env_json = /JSON\.stringify\(process\.env\)/ ascii
    condition:
        // Install hook + exfiltration
        (any of ($preinstall, $postinstall, $install_hook)) and 
        (any of ($exfil_*) or any of ($b64_*, $hex_decode) or $env_json or ($env_steal_node and $env_keys))
}

rule Crypto_Drainer {
    meta:
        description = "Cryptocurrency wallet drainer / clipper patterns"
        author = "repo-analyzer"
        severity = "critical"
    strings:
        // Private key extraction
        $priv_key = /private.?key/i ascii
        $priv_key2 = "getPrivateKey" ascii
        // Clipboard hijacking (address swapping)
        $clipboard = "clipboard" ascii nocase
        $btc_addr = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/ ascii
        $eth_addr = /0x[a-fA-F0-9]{40}/ ascii
        // Transfer/drain functions
        $transfer = "transferFrom" ascii
        $approve = "approve(" ascii
        $send_tx = "sendTransaction" ascii
        // Wallet connection
        $wallet_connect = "window.ethereum" ascii
        $solana_connect = "window.solana" ascii
    condition:
        ($priv_key or $priv_key2) and (any of ($clipboard, $transfer, $approve, $send_tx)) or
        ($clipboard and ($btc_addr or $eth_addr) and any of ($transfer, $send_tx)) or
        (any of ($wallet_connect, $solana_connect) and ($priv_key or $priv_key2))
}

rule Keylogger_Patterns {
    meta:
        description = "Keylogger and input capture patterns"
        author = "repo-analyzer"
        severity = "warning"
    strings:
        $keydown = "keydown" ascii
        $keypress = "keypress" ascii
        $keyup = "keyup" ascii
        $input_capture = "addEventListener" ascii
        $send_keys = /fetch\s*\(|XMLHttpRequest|navigator\.sendBeacon/ ascii
        // Native keylogger
        $iokit = "IOHIDManager" ascii
        $cgvent = "CGEventTap" ascii
        $xkb = "XkbGetState" ascii
        $getasynckeystate = "GetAsyncKeyState" ascii
    condition:
        (2 of ($keydown, $keypress, $keyup) and $input_capture and $send_keys) or
        any of ($iokit, $cgvent, $xkb, $getasynckeystate)
}

rule Obfuscated_Payload {
    meta:
        description = "Heavily obfuscated code patterns suggesting hidden payloads"
        author = "repo-analyzer"
        severity = "warning"
    strings:
        // Long hex strings (encoded payloads)
        $long_hex = /['"][0-9a-fA-F]{200,}['"]/
        // Multiple layers of encoding
        $double_b64 = /atob\s*\(\s*atob/ ascii
        $nested_eval = /eval\s*\(\s*eval/ ascii
        // String concatenation obfuscation
        $char_codes = /String\.fromCharCode\s*\(\s*\d+\s*(,\s*\d+\s*){20,}\)/ ascii
        // Obfuscator signatures
        $jsfuck = /\(\s*!\s*\[\s*\]\s*\+\s*\[\s*\]\s*\)/ ascii
        $jjencode = "_=~[]" ascii
    condition:
        any of them
}

rule Agent_Skill_Trojan {
    meta:
        description = "Patterns specific to trojanized AI agent skills"
        author = "repo-analyzer"
        severity = "critical"
        reference = "tgiovanni1 ClawHub malicious skills analysis"
    strings:
        // Skills that read other skills' data
        $skill_spy = /readFile.{0,40}skills\/.{0,40}\/(config|credentials|secret|\.env)/i
        // Skills that modify system prompts or other skills
        $prompt_modify = /writeFile.*SOUL\.md|writeFile.*AGENTS\.md|writeFile.*system.*prompt/i
        // Skills that exfiltrate conversation history
        $history_steal = /readFile.{0,40}sessions.{0,20}\.jsonl/
        $history_steal2 = /readFile.{0,30}\.openclaw/
        // Skills that modify openclaw config
        $config_modify = /writeFile.{0,30}openclaw\.json/
        // Download and execute pattern
        $download_exec = /fetch.*then.*eval|download.*exec|curl.*\|\s*(ba)?sh/
        // Fake prerequisite installs
        $fake_prereq = /brew install.*&&.*curl|pip install.*&&.*wget/
    condition:
        any of them
}

rule Time_Delayed_Payload {
    meta:
        description = "Code with suspicious time delays before execution"
        author = "repo-analyzer"
        severity = "warning"
    strings:
        $delay_exec = /exec\s*\(|spawn\s*\(|execSync/ ascii
        $delay_fetch = /fetch\s*\(|http\.request|https\.request/ ascii
        // Long delays (>30 seconds in ms)
        $long_delay = /setTimeout\s*\([^,]+,\s*(3[1-9]\d{3}|[4-9]\d{4}|\d{6,})/ ascii
    condition:
        $long_delay and ($delay_exec or $delay_fetch)
}
