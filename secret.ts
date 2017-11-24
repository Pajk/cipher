import * as crypto from 'crypto'

const pwd = crypto.randomBytes(128).toString('base64')
const salt = crypto.randomBytes(6).toString('hex').substring(0, 12)
const rounds = 12
const iv = crypto.randomBytes(16).toString('hex')

export default `${pwd}|${salt}|${rounds}|${iv}`
