/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'
import dns from 'node:dns'
import net from 'node:net'
import { URL } from 'node:url'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

function isPrivateIP (ip: string): boolean {
  if (net.isIPv4(ip)) {
    const parts = ip.split('.').map(Number)
    if (parts.length !== 4 || parts.some(isNaN)) {
      return true
    }

    // 127.0.0.0/8 (Loopback)
    if (parts[0] === 127) return true
    // 10.0.0.0/8 (Private)
    if (parts[0] === 10) return true
    // 172.16.0.0/12 (Private)
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true
    // 192.168.0.0/16 (Private)
    if (parts[0] === 192 && parts[1] === 168) return true
    // 169.254.0.0/16 (Link-Local)
    if (parts[0] === 169 && parts[1] === 254) return true
    // 0.0.0.0/8 (Broadcast/Unspecified)
    if (parts[0] === 0) return true
    // 224.0.0.0/4 (Multicast)
    if (parts[0] >= 224 && parts[0] <= 239) return true
    // 255.255.255.255 (Limited Broadcast)
    if (parts[0] === 255) return true

    return false
  } else if (net.isIPv6(ip)) {
    const cleanIp = ip.toLowerCase().trim()
    // Loopback: ::1
    if (cleanIp === '::1' || cleanIp === '0:0:0:0:0:0:0:1') return true
    // Unspecified: ::
    if (cleanIp === '::' || cleanIp === '0:0:0:0:0:0:0:0') return true
    // Link-local: fe80::/10 (starts with fe8, fe9, fea, feb)
    if (/^fe[89ab]/i.test(cleanIp)) return true
    // Unique local / Private: fc00::/7 (starts with fc or fd)
    if (/^f[cd]/i.test(cleanIp)) return true
    // Multicast: ff00::/8 (starts with ff)
    if (/^ff/i.test(cleanIp)) return true

    // Check IPv4-mapped IPv6 address (e.g. ::ffff:127.0.0.1)
    if (cleanIp.startsWith('::ffff:')) {
      const ipv4Part = cleanIp.slice(7)
      if (net.isIPv4(ipv4Part)) {
        return isPrivateIP(ipv4Part)
      }
    }
    return false
  }
  return true
}

async function isSafeUrl (urlString: string): Promise<boolean> {
  try {
    const parsedUrl = new URL(urlString)
    if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
      return false
    }

    const hostname = parsedUrl.hostname
    if (!hostname) {
      return false
    }

    const cleanHostname = hostname.replace(/^\[|\]$/g, '')

    if (net.isIP(cleanHostname)) {
      return !isPrivateIP(cleanHostname)
    }

    const lowerHost = cleanHostname.toLowerCase()
    if (lowerHost === 'localhost' || lowerHost.endsWith('.local') || lowerHost.endsWith('.localhost')) {
      return false
    }

    try {
      const addresses = await dns.promises.lookup(cleanHostname, { all: true })
      for (const addr of addresses) {
        if (isPrivateIP(addr.address)) {
          return false
        }
      }
    } catch (dnsErr) {
      return false
    }

    return true
  } catch (err) {
    return false
  }
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        if (!await isSafeUrl(url)) {
          next(new Error('Blocked SSRF attempt to unsafe/private address'))
          return
        }
        try {
          const response = await fetch(url)
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
