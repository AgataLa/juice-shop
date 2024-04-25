/*
 * Copyright (c) 2014-2023 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { UserModel } from '../models/user'
import challengeUtils = require('../lib/challengeUtils')
import * as utils from '../lib/utils'

const security = require('../lib/insecurity')
const cache = require('../data/datacache')
const challenges = cache.challenges

module.exports = function updateUserProfile () {
  return (req: Request, res: Response, next: NextFunction) => {
    const loggedInUser = security.authenticatedUsers.get(req.cookies.token)

    if (loggedInUser) {
      UserModel.findByPk(loggedInUser.data.id).then((user: UserModel | null) => {
        if (user != null) {
          challengeUtils.solveIf(challenges.csrfChallenge, () => {
            return ((req.headers.origin?.includes('://htmledit.squarefree.com')) ??
              (req.headers.referer?.includes('://htmledit.squarefree.com'))) &&
              req.body.username !== user.username
          })
          let new_username = req.body.username
          if(new_username === undefined || !new_username.match(/^[a-zA-Z0-9]+[a-zA-Z0-9_\-.]+$/)) {
            res.status(400).send(res.__('Username can only contain letters, numbers and _ - . signs.'))
            return
          }
          void user.update({ username: new_username }).then((savedUser: UserModel) => {
            // @ts-expect-error FIXME some properties missing in savedUser
            savedUser = utils.queryResultToJson(savedUser)
            const updatedToken = security.authorize(savedUser)
            security.authenticatedUsers.put(updatedToken, savedUser)
            res.cookie('token', updatedToken)
            res.location(process.env.BASE_PATH + '/profile')
            res.redirect(process.env.BASE_PATH + '/profile')
          })
        }
      }).catch((error: Error) => {
        next(error)
      })
    } else {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
    }
  }
}
