require('dotenv').config();
const axios = require('axios');
const { ethers } = require('ethers');
const crypto = require('crypto');
const UserAgent = require('user-agents');
const readline = require('readline').createInterface({
  input: process.stdin,
  output: process.stdout
});
const fs = require('fs').promises;
const { HttpsProxyAgent } = require('https-proxy-agent');

const colors = {
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  red: '\x1b[31m',
  white: '\x1b[37m',
  cyan: '\x1b[36m',
  reset: '\x1b[0m',
  bold: '\x1b[1m'
};

const logger = {
  info: (msg) => console.log(`${colors.green}[✓] ${msg}${colors.reset}`),
  wallet: (msg) => console.log(`${colors.yellow}[➤] ${msg}${colors.reset}`),
  error: (msg) => console.log(`${colors.red}[✗] ${msg}${colors.reset}`),
  success: (msg) => console.log(`${colors.green}[] ${msg}${colors.reset}`),
  loading: (msg) => console.log(`${colors.cyan}[⟳] ${msg}${colors.reset}`),
  step: (msg) => console.log(`${colors.white}[➤] ${msg}${colors.reset}`),
  banner: () => {
    console.log(`${colors.cyan}${colors.bold}`);
    console.log('---------------------------------------------');
    console.log('             KiteAI Auto Bot - Bamar Airdrop Group ');
    console.log(`---------------------------------------------${colors.reset}\n`);
  },
  agent: (msg) => console.log(`${colors.white}${msg}${colors.reset}`)
};

const agents = [
  { name: 'Professor', service_id: 'deployment_KiMLvUiTydioiHm7PWZ12zJU' },
  { name: 'Crypto Buddy', service_id: 'deployment_ByVHjMD6eDb9AdekRIbyuz14' },
  { name: 'Sherlock', service_id: 'deployment_OX7sn2D0WvxGUGK8CTqsU5VJ' }
];

const loadProxies = async () => {
  try {
    const content = await fs.readFile('proxy.txt', 'utf8');
    const proxies = content.split('\n')
      .map(line => line.trim())
      .filter(line => line && !line.startsWith('#'));
    
    if (proxies.length === 0) {
      logger.info('No proxies found in proxy.txt, will use direct connection');
      return null;
    }
    
    logger.info(`Loaded ${proxies.length} proxies from proxy.txt`);
    return proxies;
  } catch (error) {
    logger.info('proxy.txt not found or empty, will use direct connection');
    return null;
  }
};

const getRandomProxy = (proxies) => {
  if (!proxies || proxies.length === 0) return null;
  return proxies[Math.floor(Math.random() * proxies.length)];
};

const createAxiosInstance = (proxy) => {
  const instance = axios.create();
  
  if (proxy) {
    const proxyUrl = proxy.startsWith('http') ? proxy : `http://${proxy}`;
    instance.defaults.httpsAgent = new HttpsProxyAgent(proxyUrl);
    instance.defaults.proxy = false;
  }
  
  return instance;
};

const loadPrompts = async () => {
  try {
    const content = await fs.readFile('prompt.txt', 'utf8');
    const lines = content.split('\n').map(line => line.trim());
    const promptGenerators = {};
    let currentAgent = null;

    for (const line of lines) {
      if (line.startsWith('[') && line.endsWith(']')) {
        currentAgent = line.slice(1, -1).trim();
        promptGenerators[currentAgent] = [];
      } else if (line && !line.startsWith('#') && currentAgent) {
        promptGenerators[currentAgent].push(line);
      }
    }

    for (const agent of agents) {
      if (!promptGenerators[agent.name] || promptGenerators[agent.name].length === 0) {
        logger.error(`No prompts found for agent ${agent.name} in prompt.txt`);
        process.exit(1);
      }
    }

    return promptGenerators;
  } catch (error) {
    logger.error(`Failed to load prompt.txt: ${error.message}`);
    process.exit(1);
  }
};

const getRandomPrompt = (agentName, promptGenerators) => {
  const prompts = promptGenerators[agentName] || [];
  return prompts[Math.floor(Math.random() * prompts.length)];
};

const userAgent = new UserAgent();
const baseHeaders = {
  'Accept': 'application/json, text/plain, */*',
  'Accept-Language': 'id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7',
  'Origin': 'https://testnet.gokite.ai',
  'Referer': 'https://testnet.gokite.ai/',
  'Sec-Fetch-Dest': 'empty',
  'Sec-Fetch-Mode': 'cors',
  'Sec-Fetch-Site': 'same-site',
  'User-Agent': userAgent.toString(),
  'Content-Type': 'application/json'
};

const encryptAddress = (address) => {
  try {
    const keyHex = '6a1c35292b7c5b769ff47d89a17e7bc4f0adfe1b462981d28e0e9f7ff20b8f8a';
    const key = Buffer.from(keyHex, 'hex');
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    
    let encrypted = cipher.update(address, 'utf8');
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    const authTag = cipher.getAuthTag();
    
    const result = Buffer.concat([iv, encrypted, authTag]);
    return result.toString('hex');
  } catch (error) {
    logger.error(`Auth token generation failed for ${address}`);
    return null;
  }
};

const extractCookies = (headers) => {
  try {
    const rawCookies = headers['set-cookie'] || [];
    const skipKeys = ['expires', 'path', 'domain', 'samesite', 'secure', 'httponly', 'max-age'];
    const cookiesDict = {};
    
    for (const cookieStr of rawCookies) {
      const parts = cookieStr.split(';');
      for (const part of parts) {
        const cookie = part.trim();
        if (cookie.includes('=')) {
          const [name, value] = cookie.split('=', 2);
          if (name && value && !skipKeys.includes(name.toLowerCase())) {
            cookiesDict[name] = value;
          }
        }
      }
    }
    
    return Object.entries(cookiesDict).map(([key, value]) => `${key}=${value}`).join('; ') || null;
  } catch (error) {
    return null;
  }
};

const getWallet = (privateKey) => {
  try {
    const wallet = new ethers.Wallet(privateKey);
    logger.info(`Wallet created: ${wallet.address}`);
    return wallet;
  } catch (error) {
    logger.error(`Invalid private key: ${error.message}`);
    return null;
  }
};

const login = async (wallet, neo_session = null, refresh_token = null, maxRetries = 3, axiosInstance) => {
  const url = 'https://neo.prod.gokite.ai/v2/signin';
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      logger.loading(`Logging in to ${wallet.address} (Attempt ${attempt}/${maxRetries})`);

      const authToken = encryptAddress(wallet.address);
      if (!authToken) return null;
      
      const loginHeaders = {
        ...baseHeaders,
        'Authorization': authToken,
      };

      if (neo_session || refresh_token) {
        const cookies = [];
        if (neo_session) cookies.push(`neo_session=${neo_session}`);
        if (refresh_token) cookies.push(`refresh_token=${refresh_token}`);
        loginHeaders['Cookie'] = cookies.join('; ');
      }
      
      const body = { eoa: wallet.address };
      const response = await axiosInstance.post(url, body, { headers: loginHeaders });
      
      if (response.data.error) {
        logger.error(`Login failed for ${wallet.address}: ${response.data.error}`);
        return null;
      }
      
      const { access_token, aa_address, displayed_name, avatar_url } = response.data.data;
      const cookieHeader = extractCookies(response.headers);

      let resolved_aa_address = aa_address;
      if (!resolved_aa_address) {
        const profile = await getUserProfile(access_token, axiosInstance);
        resolved_aa_address = profile?.profile?.smart_account_address;
        if (!resolved_aa_address) {
          logger.error(`No aa_address found for ${wallet.address}`);
          return null;
        }
      }
      
      logger.success(`Login successful for ${wallet.address}`);
      return { access_token, aa_address: resolved_aa_address, displayed_name, avatar_url, cookieHeader };
    } catch (error) {
      const errorMessage = error.response?.data?.error || error.message;
      if (attempt === maxRetries) {
        logger.error(`Login failed for ${wallet.address} after ${maxRetries} attempts: ${errorMessage}. Check cookies or contact Kite AI support.`);
        return null;
      }
      await new Promise(resolve => setTimeout(resolve, 2000));
    }
  }
};

const getUserProfile = async (access_token, axiosInstance) => {
  try {
    const response = await axiosInstance.get('https://ozone-point-system.prod.gokite.ai/me', {
      headers: { ...baseHeaders, Authorization: `Bearer ${access_token}` }
    });
    
    if (response.data.error) {
      logger.error(`Failed to fetch profile: ${response.data.error}`);
      return null;
    }
    
    return response.data.data;
  } catch (error) {
    logger.error(`Profile fetch error: ${error.message}`);
    return null;
  }
};

const interactWithAgent = async (access_token, aa_address, cookieHeader, agent, prompt, interactionCount, axiosInstance) => {
  try {
    if (!aa_address) {
      logger.error(`Cannot interact with ${agent.name}: No aa_address`);
      return null;
    }
    
    logger.step(`Interaction ${interactionCount} - Prompts : ${prompt}`);

    const inferenceHeaders = {
      ...baseHeaders,
      Authorization: `Bearer ${access_token}`,
      Accept: 'text/event-stream'
    };
    if (cookieHeader) {
      inferenceHeaders['Cookie'] = cookieHeader;
    }
    
    const inferenceResponse = await axiosInstance.post('https://ozone-point-system.prod.gokite.ai/agent/inference', {
      service_id: agent.service_id,
      subnet: 'kite_ai_labs',
      stream: true,
      body: { stream: true, message: prompt }
    }, {
      headers: inferenceHeaders
    });

    let output = '';
    const lines = inferenceResponse.data.split('\n');
    for (const line of lines) {
      if (line.startsWith('data: ') && line !== 'data: [DONE]') {
        try {
          const data = JSON.parse(line.replace('data: ', ''));
          if (data.choices && data.choices[0].delta.content) {
            output += data.choices[0].delta.content;
            if (output.length > 100) {
              output = output.substring(0, 100) + '...';
              break;
            }
          }
        } catch (e) {}
      }
    }

    const receiptHeaders = {
      ...baseHeaders,
      Authorization: `Bearer ${access_token}`
    };
    if (cookieHeader) {
      receiptHeaders['Cookie'] = cookieHeader;
    }
    
    const receiptResponse = await axiosInstance.post('https://neo.prod.gokite.ai/v2/submit_receipt', {
      address: aa_address,
      service_id: agent.service_id,
      input: [{ type: 'text/plain', value: prompt }],
      output: [{ type: 'text/plain', value: output || 'No response' }]
    }, {
      headers: receiptHeaders
    });
    
    if (receiptResponse.data.error) {
      logger.error(`Receipt submission failed for ${agent.name}: ${receiptResponse.data.error}`);
      return null;
    }
    
    const { id } = receiptResponse.data.data;
    logger.step(`Interaction ${interactionCount} - Receipt submitted, ID: ${id}`);

    let statusResponse;
    let attempts = 0;
    const maxAttempts = 10;
    while (attempts < maxAttempts) {
      statusResponse = await axiosInstance.get(`https://neo.prod.gokite.ai/v1/inference?id=${id}`, {
        headers: { ...baseHeaders, Authorization: `Bearer ${access_token}` }
      });
      
      if (statusResponse.data.data.processed_at && statusResponse.data.data.tx_hash) {
        logger.step(`Interaction ${interactionCount} - Inference processed, tx_hash : ${statusResponse.data.data.tx_hash}`);
        return statusResponse.data.data;
      }
      
      attempts++;
      await new Promise(resolve => setTimeout(resolve, 2000));
    }
    
    logger.error(`Inference status not completed after ${maxAttempts} attempts`);
    return null;
  } catch (error) {
    logger.error(`Error interacting with ${agent.name}: ${error.response?.data?.error || error.message}`);
    return null;
  }
};

const getNextRunTime = () => {
  const now = new Date();
  now.setHours(now.getHours() + 6); 
  now.setMinutes(0);
  now.setSeconds(0);
  now.setMilliseconds(0);
  return now;
};

const displayCountdown = (nextRunTime, interactionCount, proxies) => {
  const updateCountdown = () => {
    const now = new Date();
    const timeLeft = nextRunTime - now;
    
    if (timeLeft <= 0) {
      logger.info('Starting new run...');
      clearInterval(countdownInterval);
      dailyRun(interactionCount, proxies); 
      return;
    }

    const hours = Math.floor(timeLeft / (1000 * 60 * 60));
    const minutes = Math.floor((timeLeft % (1000 * 60 * 60)) / (1000 * 60));
    const seconds = Math.floor((timeLeft % (1000 * 60)) / 1000);
    
    process.stdout.write(`\r${colors.cyan}[⏰] Next run in: ${hours}h ${minutes}m ${seconds}s${colors.reset} `);
  };

  updateCountdown();
  const countdownInterval = setInterval(updateCountdown, 1000);
};

let interactionCount = null;

const processWallet = async ({ privateKey, neo_session, refresh_token }, interactionCount, promptGenerators, proxies) => {
  try {
    const proxy = getRandomProxy(proxies);
    const axiosInstance = createAxiosInstance(proxy);
    
    if (proxy) {
      logger.info(`Using proxy: ${proxy}`);
    } else {
      logger.info('Using direct connection (no proxy)');
    }

    const wallet = getWallet(privateKey);
    if (!wallet) return;
    
    logger.wallet(`Processing wallet: ${wallet.address}`);

    const loginData = await login(wallet, neo_session, refresh_token, 3, axiosInstance);
    if (!loginData) return;
    
    const { access_token, aa_address, displayed_name, cookieHeader } = loginData;
    if (!aa_address) return;

    const profile = await getUserProfile(access_token, axiosInstance);
    if (!profile) return;

    logger.info(`User: ${profile.profile.displayed_name || displayed_name || 'Unknown'}`);
    logger.info(`EOA Address: ${profile.profile.eoa_address || wallet.address}`);
    logger.info(`Smart Account: ${profile.profile.smart_account_address || aa_address}`);
    logger.info(`Total XP Points: ${profile.profile.total_xp_points || 0}`);
    logger.info(`Referral Code: ${profile.profile.referral_code || 'None'}`);
    logger.info(`Badges Minted: ${profile.profile.badges_minted?.length || 0}`);
    logger.info(`Twitter Connected: ${profile.social_accounts?.twitter?.id ? 'Yes' : 'No'}`);

    for (const agent of agents) {
      const agentHeader = agent.name === 'Professor' ? '\n----- PROFESSOR -----' : 
                         agent.name === 'Crypto Buddy' ? '----- CRYPTO BUDDY -----' : 
                         '----- SHERLOCK -----';
      logger.agent(`${agentHeader}`);
      
      for (let i = 0; i < interactionCount; i++) {
        const prompt = getRandomPrompt(agent.name, promptGenerators);
        await interactWithAgent(access_token, aa_address, cookieHeader, agent, prompt, i + 1, axiosInstance);
        await new Promise(resolve => setTimeout(resolve, 3000));
      }
      logger.agent('\n'); 
    }
    
    return { success: true, address: wallet.address };
  } catch (error) {
    logger.error(`Error processing wallet: ${error.message}`);
    return { success: false, address: privateKey ? new ethers.Wallet(privateKey).address : 'Unknown' };
  }
};

const dailyRun = async (count, proxies) => {
  logger.banner();
  
  const promptGenerators = await loadPrompts();
  
  const wallets = Object.keys(process.env)
    .filter(key => key.startsWith('PRIVATE_KEY_'))
    .map(key => ({
      privateKey: process.env[key],
      neo_session: process.env[`NEO_SESSION_${key.split('_')[2]}`] || null,
      refresh_token: process.env[`REFRESH_TOKEN_${key.split('_')[2]}`] || null
    }))
    .filter(wallet => wallet.privateKey && wallet.privateKey.trim() !== '');
  
  if (wallets.length === 0) {
    logger.error('No valid private keys found in .env');
    return;
  }

  if (interactionCount === null) {
    interactionCount = await new Promise((resolve) => {
      readline.question('Enter the number of interactions per agent: ', (answer) => {
        const count = parseInt(answer);
        if (isNaN(count) || count < 1 || count > 99999) {
          logger.error('Invalid input. Please enter a number between 1 and 99999.');
          process.exit(1);
        }
        resolve(count);
      });
    });
  }

  const results = await Promise.all(
    wallets.map(wallet => processWallet(wallet, interactionCount, promptGenerators, proxies))
  );

  const successfulWallets = results.filter(r => r?.success).length;
  logger.success(`Completed processing ${successfulWallets}/${wallets.length} wallets successfully`);
  
  const nextRunTime = getNextRunTime();
  logger.info(`Next run scheduled at: ${nextRunTime.toLocaleString()}`);
  displayCountdown(nextRunTime, interactionCount, proxies);
};

const main = async () => {
  try {
    const proxies = await loadProxies();
    await dailyRun(interactionCount, proxies);
  } catch (error) {
    logger.error(`Bot error: ${error.response?.data?.error || error.message}`);
    const nextRunTime = getNextRunTime();
    logger.info(`Next run scheduled at: ${nextRunTime.toLocaleString()}`);
    displayCountdown(nextRunTime, interactionCount, await loadProxies());
  }
};

main().catch(error => logger.error(`Bot error: ${error.response?.data?.error || error.message}`));
