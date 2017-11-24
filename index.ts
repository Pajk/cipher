import * as crypto from 'crypto'

const DEFAULT_DERIVED_KEY_ITERATIONS_MIN = 200000
const DEFAULT_DERIVED_KEY_ITERATIONS_MAX = 250000

const DERIVED_KEY_ALGORITHM = 'sha256'
const ENC_ALGORITHM = 'aes-256-cbc'
const HMAC_ALGORITHM = 'sha256'
const HMAC_KEY_SIZE = 32
const PASSWORD_KEY_SIZE = 32
const SALT_LENGTH = 12

/**
 * Initialization vector if not provided is generated randomly for each value
 * @param keys key_password|key_salt|key_rounds|[cipher_iv]
 */
export const parseEncryptionKeys = keys => {
    const parts = keys.split('|')

    if (parts.length !== 4 && parts.length !== 3) {
        throw new Error('Invalid format of encryption keys, should be "key_password|key_salt|key_rounds|[cipher_iv]"')
    }

    const rounds = parseInt(parts[2], 10)

    if (!rounds || rounds < 0) {
        throw new Error('Invalid number of rounds in encryption keys')
    }

    return {
        key: parts[0],
        salt: parts[1],
        rounds,
        iv: parts.length === 4 ? parts[3] : null,
    }
}

export const createEncrypter = async (key, salt?, rounds?, iv?) => {
    const keyInfo = await getKeyFromPassword(key, salt, rounds)

    return text => {
        const parts = encrypt(text, keyInfo, iv)

        return packEncryptedContent(parts)
    }
}

export const createDecrypter = key => async content => {
    const parts = unpackEncryptedContent(content)

    const keyInfo = await getKeyFromPassword(key, parts.salt, parts.rounds)

    return decrypt(parts, keyInfo)
}

interface IKeyInfo {
    salt: string
    key: Buffer
    hmac: Buffer
    rounds: number
}

interface IEncryptedContent {
    hmac: string
    iv: string
    salt: string
    rounds: number
    content: string
}

function encrypt(text, keyInfo: IKeyInfo, ivValue?: string): IEncryptedContent {
    const iv = generateIV(ivValue)
    const ivHex = iv.toString('hex')
    const encryptTool = crypto.createCipheriv(ENC_ALGORITHM, keyInfo.key, iv)
    const hmacTool = crypto.createHmac(HMAC_ALGORITHM, keyInfo.hmac)
    const saltHex = keyInfo.salt
    const pbkdf2Rounds = keyInfo.rounds

    // Perform encryption
    let encryptedContent = encryptTool.update(text, 'utf8', 'base64')
    encryptedContent += encryptTool.final('base64')

    // Generate hmac
    hmacTool.update(encryptedContent)
    hmacTool.update(ivHex)
    hmacTool.update(saltHex)
    const hmacHex = hmacTool.digest('hex')

    return {
        hmac: hmacHex,
        iv: ivHex,
        salt: saltHex,
        rounds: pbkdf2Rounds,
        content: encryptedContent,
    }
}

function decrypt(parts: IEncryptedContent, keyInfo: IKeyInfo) {
    // Extract the components
    const content = parts.content
    const iv = new Buffer(parts.iv, 'hex')
    const salt = parts.salt
    const hmacData = parts.hmac

    // Get HMAC tool
    const hmacTool = crypto.createHmac(HMAC_ALGORITHM, keyInfo.hmac)

    // Generate the HMAC
    hmacTool.update(content)
    hmacTool.update(parts.iv)
    hmacTool.update(salt)

    const newHmaxHex = hmacTool.digest('hex')

    // Check hmac for tampering
    if (constantTimeCompare(hmacData, newHmaxHex) !== true) {
        throw new Error('Authentication failed while decrypting content')
    }

    // Decrypt
    const decryptTool = crypto.createDecipheriv(ENC_ALGORITHM, keyInfo.key, iv)
    const decryptedText = decryptTool.update(content, 'base64', 'utf8')

    return decryptedText + decryptTool.final('utf8')
}

async function getKeyFromPassword(password: string, salt?: string, rounds?: number): Promise<IKeyInfo> {
    rounds = sanitiseRounds(rounds)
    salt = sanitiseSalt(salt)

    const bits = (PASSWORD_KEY_SIZE + HMAC_KEY_SIZE)  * 8
    const keyData = await pbkdf2(
        password,
        salt,
        rounds,
        bits,
        DERIVED_KEY_ALGORITHM,
    )
    const keyHex = await keyData.toString('hex')
    const dkhLength = keyHex.length
    const keyBuffer = new Buffer(keyHex.substr(0, dkhLength / 2), 'hex')
    const hmacBuffer = new Buffer(keyHex.substr(dkhLength / 2, dkhLength / 2), 'hex')

    return {
        salt,
        key: keyBuffer,
        hmac: hmacBuffer,
        rounds,
    }
}

function sanitiseRounds(rounds) {
    return rounds || getRandomInRange(
        DEFAULT_DERIVED_KEY_ITERATIONS_MIN,
        DEFAULT_DERIVED_KEY_ITERATIONS_MAX,
    )
}

function sanitiseSalt(salt) {
    return salt || generateSalt(SALT_LENGTH)
}

function getRandomInRange(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min
}

function generateIV(ivValue) {
    if (ivValue) {
        return new Buffer(ivValue, 'hex')
    }

    return crypto.randomBytes(16)
}

function generateSalt(length) {
    const genLen = length % 2 ? length + 1 : length

    return crypto.randomBytes(genLen / 2)
        .toString('hex')
        .substring(0, length)
}

function pbkdf2(password, salt, rounds, bits, digest) {
    return new Promise<Buffer>((resolve, reject) => {
        crypto.pbkdf2(password, salt, rounds, bits / 8, digest, (err, keyInfo) => {
            if (err) {
                reject(err)
            } else {
                resolve(keyInfo)
            }
        })
    })
}

function packEncryptedContent(data: IEncryptedContent) {
    return [
        data.content,
        data.iv,
        data.salt,
        data.hmac,
        data.rounds,
    ].join('$')
}

function unpackEncryptedContent(encryptedContent: string): IEncryptedContent {
    const components = encryptedContent.split('$')

    if (components.length !== 5) {
        throw new Error('Decryption error - unexpected number of encrypted components')
    }

    return {
        content: components[0],
        iv: components[1],
        salt: components[2],
        hmac: components[3],
        rounds: parseInt(components[4], 10),
    }
}

function constantTimeCompare(val1, val2) {
    let sentinel
    for (let i = 0; i <= (val1.length - 1); i += 1) {
        /* tslint:disable-next-line */
        sentinel |= val1.charCodeAt(i) ^ val2.charCodeAt(i)
    }
    return sentinel === 0
}
