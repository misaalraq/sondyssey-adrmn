const { readFileSync } = require("fs");
const sol = require("@solana/web3.js");
const bs58 = require("bs58");
const fetch = require("node-fetch");
const prompts = require('prompts');
const nacl = require("tweetnacl");

const captchaKey = 'INSERT_YOUR_2CAPTCHA_KEY_HERE';
const rpc = 'https://devnet.sonic.game/';
const connection = new sol.Connection(rpc, 'confirmed');
const keypairs = [];

const defaultHeaders = {
    'accept': '*/*',
    'accept-language': 'en-US,en;q=0.7',
    'content-type': 'application/json',
    'priority': 'u=1, i',
    'sec-ch-ua': '"Not/A)Brand";v="8", "Chromium";v="126", "Brave";v="126"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-site',
    'sec-gpc': '1',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
};

function generateRandomAddresses(count) {
    const addresses = [];
    for (let i = 0; i < count; i++) {
        const keypair = sol.Keypair.generate();
        addresses.push(keypair.publicKey.toString());
    }
    return addresses;
}

function getKeypairFromPrivateKey(privateKey) {
    const decoded = bs58.decode(privateKey);
    if (decoded.length !== 64) {
        throw new Error(`Invalid private key length. Expected 64 bytes, got ${decoded.length} bytes.`);
    }
    return sol.Keypair.fromSecretKey(decoded);
}

const sendTransaction = (transaction, keyPair) => new Promise(async (resolve) => {
    try {
        transaction.partialSign(keyPair);
        const rawTransaction = transaction.serialize();
        const signature = await connection.sendRawTransaction(rawTransaction);
        await connection.confirmTransaction(signature);
        resolve(signature);
    } catch (error) {
        resolve(error);
    }
});

const delay = (seconds) => {
    return new Promise((resolve) => {
        setTimeout(resolve, seconds * 1000);
    });
}

const twocaptcha_turnstile = (sitekey, pageurl) => new Promise(async (resolve) => {
    try {
        const getToken = await fetch(`https://2captcha.com/in.php?key=${captchaKey}&method=turnstile&sitekey=${sitekey}&pageurl=${pageurl}&json=1`, {
            method: 'GET',
        })
        .then(res => res.text())
        .then(res => {
            if (res == 'ERROR_WRONG_USER_KEY' || res == 'ERROR_ZERO_BALANCE') {
                return resolve(res);
            } else {
                return res.split('|');
            }
        });

        if (getToken[0] != 'OK') {
            resolve('FAILED_GETTING_TOKEN');
        }
    
        const task = getToken[1];

        for (let i = 0; i < 60; i++) {
            const token = await fetch(
                `https://2captcha.com/res.php?key=${captchaKey}&action=get&id=${task}&json=1`
            ).then(res => res.json());
            
            if (token.status == 1) {
                resolve(token);
                break;
            }
            await delay(2);
        }
    } catch (error) {
        resolve('FAILED_GETTING_TOKEN');
    }
});

const claimFaucet = (address) => new Promise(async (resolve) => {
    let success = false;
    
    while (!success) {
        const bearer = await twocaptcha_turnstile('0x4AAAAAAAc6HG1RMG_8EHSC', 'https://faucet.sonic.game/#/');
        if (bearer == 'ERROR_WRONG_USER_KEY' || bearer == 'ERROR_ZERO_BALANCE' || bearer == 'FAILED_GETTING_TOKEN') {
            success = true;
            resolve(`Failed claim, ${bearer}`);
        }
    
        try {
            const res = await fetch(`https://faucet-api.sonic.game/airdrop/${address}/1/${bearer.request}`, {
                headers: {
                    "Accept": "application/json, text/plain, */*",
                    "Content-Type": "application/json",
                    "Accept-Language": "en-US,en;q=0.9,id;q=0.8",
                    "Dnt": "1",
                    "Origin": "https://faucet.sonic.game",
                    "Priority": "u=1, i",
                    "Referer": "https://faucet.sonic.game/",
                    "User-Agent": bearer.useragent,
                    "sec-ch-ua-mobile": "?0",
                    "sec-ch-ua-platform": "Windows",
                }
            }).then(res => res.json());
    
            if (res.status == 'ok') {
                success = true;
                resolve(`Successfully claim faucet 1 SOL!`);
            }
        } catch (error) {}
    }
});

const getLoginToken = (keyPair) => new Promise(async (resolve) => {
    let success = false;
    while (!success) {
        try {
            const message = await fetch(`https://odyssey-api.sonic.game/auth/sonic/challenge?wallet=${keyPair.publicKey}`, {
                headers: defaultHeaders
            }).then(res => res.json());
        
            const sign = nacl.sign.detached(Buffer.from(message.data), keyPair.secretKey);
            const signature = Buffer.from(sign).toString('base64');
            const publicKey = keyPair.publicKey.toBase58();
            const addressEncoded = Buffer.from(keyPair.publicKey.toBytes()).toString("base64")
            const authorize = await fetch('https://odyssey-api.sonic.game/auth/sonic/authorize', {
                method: 'POST',
                headers: defaultHeaders,
                body: JSON.stringify({
                    'address': `${publicKey}`,
                    'address_encoded': `${addressEncoded}`,
                    'signature': `${signature}`
                })
            }).then(res => res.json());
        
            const token = authorize.data.token;
            success = true;
            resolve(token);
        } catch (e) {}
    }
});

const dailyCheckin = (keyPair, auth) => new Promise(async (resolve) => {
    let success = false;
    while (!success) {
        try {
            const data = await fetch(`https://odyssey-api.sonic.game/user/check-in/transaction`, {
                headers: {
                    ...defaultHeaders,
                    'authorization': `${auth}`
                }
            }).then(res => res.json());
            
            if (data.message == 'current account already checked in') {
                success = true;
                resolve('Already check in today!');
            }
            
            if (data.data) {
                const transactionBuffer = Buffer.from(data.data.hash, "base64");
                const transaction = sol.Transaction.from(transactionBuffer);
                const signature = await sendTransaction(transaction, keyPair);
                const checkin = await fetch('https://odyssey-api.sonic.game/user/check-in', {
                    method: 'POST',
                    headers: {
                        ...defaultHeaders,
                        'authorization': `${auth}`
                    },
                    body: JSON.stringify({
                        'hash': `${signature}`
                    })
                }).then(res => res.json());
                
                success = true;
                resolve(`Successfully to check in, day ${checkin.data.accumulative_days}!`);
            }
        } catch (e) {}
    }
});

const dailyMilestone = (auth, stage) => new Promise(async (resolve) => {
    let success = false;
    while (!success) {
        try {
            await fetch('https://odyssey-api.sonic.game/user/transactions/state/daily', {
                method: 'GET',
                headers: {
                    ...defaultHeaders,
                    'authorization': `${auth}`
                },
            });

            const data = await fetch('https://odyssey-api.sonic.game/user/transactions/rewards/claim', {
                method: 'POST',
                headers: {
                    ...defaultHeaders,
                    'authorization': `${auth}`
                },
                body: JSON.stringify({
                    'stage': stage
                })
            }).then(res => res.json());
            
            if (data.message == 'interact rewards already claimed') {
                success = true;
                resolve(`Already claim milestone ${stage}!`);
            }
            
            if (data.data) {
                success = true;
                resolve(`Successfully to claim milestone ${stage}.`)
            }
        } catch (e) {}
    }
});

const openBox = (keyPair, auth) => new Promise(async (resolve) => {
    let success = false;
    while (!success) {
        try {
            const data = await fetch(`https://odyssey-api.sonic.game/user/rewards/mystery-box/build-tx`, {
                headers: {
                    ...defaultHeaders,
                    'authorization': auth
                }
            }).then(res => res.json());

            if (data.data) {
                const transactionBuffer = Buffer.from(data.data.hash, "base64");
                const transaction = sol.Transaction.from(transactionBuffer);
                transaction.partialSign(keyPair);
                const signature = await sendTransaction(transaction, keyPair);
                const open = await fetch('https://odyssey-api.sonic.game/user/rewards/mystery-box/open', {
                    method: 'POST',
                    headers: {
                        ...defaultHeaders,
                        'authorization': auth
                    },
                    body: JSON.stringify({
                        'hash': `${signature}`
                    })
                }).then(res => res.json());
                
                success = true;
                resolve(`Open box, ${open.message}!`);
            }
        } catch (e) {}
    }
});

const withdrawAsset = (keyPair, auth, id, amount) => new Promise(async (resolve) => {
    let success = false;
    while (!success) {
        try {
            const data = await fetch(`https://odyssey-api.sonic.game/user/transaction`, {
                method: 'POST',
                headers: {
                    ...defaultHeaders,
                    'authorization': auth
                },
                body: JSON.stringify({
                    'asset_id': `${id}`,
                    'amount': `${amount}`,
                    'memo': ''
                })
            }).then(res => res.json());

            if (data.message == 'withdraw') {
                success = true;
                resolve(`Already withdraw ${amount}!`);
            }

            if (data.data) {
                const transactionBuffer = Buffer.from(data.data.hash, "base64");
                const transaction = sol.Transaction.from(transactionBuffer);
                transaction.partialSign(keyPair);
                const signature = await sendTransaction(transaction, keyPair);
                const withdraw = await fetch('https://odyssey-api.sonic.game/user/transactions/withdraw', {
                    method: 'POST',
                    headers: {
                        ...defaultHeaders,
                        'authorization': auth
                    },
                    body: JSON.stringify({
                        'hash': `${signature}`
                    })
                }).then(res => res.json());
                
                success = true;
                resolve(`Successfully to withdraw ${amount}!`);
            }
        } catch (e) {}
    }
});

(async () => {
    const action = await prompts({
        type: 'select',
        name: 'value',
        message: 'Select action',
        choices: [
            { title: 'Generate Addresses', value: 'generate_addresses' },
            { title: 'Claim Faucet', value: 'claim_faucet' },
            { title: 'Daily Check-in', value: 'daily_checkin' },
            { title: 'Daily Milestone', value: 'daily_milestone' },
            { title: 'Open Box', value: 'open_box' },
            { title: 'Withdraw Asset', value: 'withdraw_asset' },
            { title: 'Exit', value: 'exit' }
        ],
        initial: 0
    });

    switch (action.value) {
        case 'generate_addresses':
            const count = await prompts({
                type: 'number',
                name: 'value',
                message: 'Enter number of addresses to generate',
                initial: 1,
                validate: value => value > 0 ? true : 'Number must be greater than 0'
            });

            const addresses = generateRandomAddresses(count.value);
            console.log('Generated Addresses:');
            addresses.forEach(address => console.log(address));
            break;

        case 'claim_faucet':
            const privateKey = await prompts({
                type: 'text',
                name: 'value',
                message: 'Enter private key to claim faucet'
            });

            const keyPair = getKeypairFromPrivateKey(privateKey.value);
            const claimResult = await claimFaucet(keyPair.publicKey.toString());
            console.log(claimResult);
            break;

        case 'daily_checkin':
            const privateKeyCheckin = await prompts({
                type: 'text',
                name: 'value',
                message: 'Enter private key for daily check-in'
            });

            const keyPairCheckin = getKeypairFromPrivateKey(privateKeyCheckin.value);
            const authCheckin = await getLoginToken(keyPairCheckin);
            const checkinResult = await dailyCheckin(keyPairCheckin, authCheckin);
            console.log(checkinResult);
            break;

        case 'daily_milestone':
            const privateKeyMilestone = await prompts({
                type: 'text',
                name: 'value',
                message: 'Enter private key for daily milestone'
            });

            const keyPairMilestone = getKeypairFromPrivateKey(privateKeyMilestone.value);
            const authMilestone = await getLoginToken(keyPairMilestone);
            const stage = await prompts({
                type: 'number',
                name: 'value',
                message: 'Enter milestone stage to claim',
                initial: 1,
                validate: value => value > 0 ? true : 'Number must be greater than 0'
            });

            const milestoneResult = await dailyMilestone(authMilestone, stage.value);
            console.log(milestoneResult);
            break;

        case 'open_box':
            const privateKeyBox = await prompts({
                type: 'text',
                name: 'value',
                message: 'Enter private key for mystery box'
            });

            const keyPairBox = getKeypairFromPrivateKey(privateKeyBox.value);
            const authBox = await getLoginToken(keyPairBox);
            const openBoxResult = await openBox(keyPairBox, authBox);
            console.log(openBoxResult);
            break;

        case 'withdraw_asset':
            const privateKeyWithdraw = await prompts({
                type: 'text',
                name: 'value',
                message: 'Enter private key for asset withdrawal'
            });

            const keyPairWithdraw = getKeypairFromPrivateKey(privateKeyWithdraw.value);
            const authWithdraw = await getLoginToken(keyPairWithdraw);
            const assetId = await prompts({
                type: 'text',
                name: 'value',
                message: 'Enter asset ID to withdraw'
            });

            const amount = await prompts({
                type: 'number',
                name: 'value',
                message: 'Enter amount to withdraw',
                initial: 1,
                validate: value => value > 0 ? true : 'Amount must be greater than 0'
            });

            const withdrawResult = await withdrawAsset(keyPairWithdraw, authWithdraw, assetId.value, amount.value);
            console.log(withdrawResult);
            break;

        case 'exit':
            console.log('Exiting...');
            break;

        default:
            console.log('Invalid choice');
            break;
    }
})();
