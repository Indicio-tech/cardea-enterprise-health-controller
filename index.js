require('dotenv').config()
const bodyParser = require('body-parser')
const express = require('express')
const http = require('http')
const jwt = require('jsonwebtoken')
const passport = require('passport')
const session = require('express-session')
const Util = require('./util')

const Sequelize = require('sequelize')
// initalize sequelize with session store
const SequelizeStore = require('connect-session-sequelize')(session.Store)

const Images = require('./agentLogic/images')

// Import environment variables for use via an .env file in a non-containerized context
const dotenv = require('dotenv')
dotenv.config()

let app = express()
let server = http.createServer(app)

module.exports.server = server

// Websockets required to make APIs work and avoid circular dependency
let Websocket = require('./websockets.js')

const Sessions = require('./agentLogic/sessions')
const Users = require('./agentLogic/users')

app.use(bodyParser.urlencoded({extended: false}))
app.use(bodyParser.json())

app.use(passport.initialize())
require('./passport-config')(passport)

server.listen(process.env.CONTROLLERPORT || 3100, () =>
  console.log(
    `Server listening at http://localhost:${
      process.env.CONTROLLERPORT || 3100
    }`,
    `\n Agent Address: ${process.env.AGENTADDRESS || 'localhost:8150'}`,
  ),
)

const agentWebhookRouter = require('./agentWebhook')

// Send all cloud agent webhooks posting to the agent webhook router
app.use('/api/controller-webhook', agentWebhookRouter)

// Present only in development to catch the secondary agent webhooks for ease of development
app.use('/api/second-controller', (req, res) => {
  console.log('Second ACA-Py Agent Webhook Message')
  res.status(200).send()
})

// -----------------------------APIs imports--------------------------------------
// Invitation request API
const Invitations = require('./agentLogic/invitations')
const Credentials = require('./agentLogic/credentials')
const IssuanceRequests = require('./agentLogic/issuanceRequests')
const Verifications = require('./agentLogic/verifications')
// -----------------------------APIs imports--------------------------------------

// (eldersonar)
app.use(
  '/api/governance-framework',
  express.static('governance-framework.json'),
)

app.use(
  '/api/governance-framework-atomic-actions',
  express.static('governance-framework-atomic-actions.json'),
)

// (eldersonar) Create database
const sequelize = new Sequelize(
  process.env.DB,
  process.env.DB_USERNAME,
  process.env.DB_PASSWORD,
  {
    host: process.env.DB_HOST,
    dialect: 'postgres',
  },
)

const myStore = new SequelizeStore({
  db: sequelize,
  tableName: 'sessions',
  checkExpirationInterval: 15 * 60 * 1000, // Storage auto cleanup
})

let sess = {
  secret: process.env.SESSION_SECRET,
  store: myStore,
  cookie: {
    maxAge: 3600 * 1000,
    httpOnly: false,
    // sameSite: 'strict' // Not enabled due to browser support; TODO: Check again after June 1, 2022
  },
  name: 'sessionId',
  resave: false, // Touch is enabled via SequelizeStore
  rolling: true, // Force the session identifier cookie to be set on every response.
  saveUninitialized: false,
}

// Use secure cookies in production
if (process.env.NODE_ENV === 'production') {
  app.set('trust proxy', 1) // trust first proxy
  sess.proxy = true // The "X-Forwarded-Proto" header will be used
  sess.cookie.secure = true // serve secure cookies
}

app.use(session(sess))

function parseCookies(request) {
  var list = {},
    rc = request.headers.cookie

  rc &&
    rc.split(';').forEach(function (cookie) {
      var parts = cookie.split('=')
      list[parts.shift().trim()] = decodeURI(parts.join('='))
    })

  return list
}

app.use(passport.session())

// (eldersonar) Session validation middleware
const verifySession = (req, res, next) => {
  const cookies = parseCookies(req)

  if (cookies.sessionId) {
    let sessionId = cookies.sessionId.split('.')[0]
    sessionId = sessionId.split('s%3A')[1]

    if (sessionId === req.sessionID) {
      // console.log('100% session ID match')
      next()
    } else {
      console.log('Unauthorized')
      res.redirect(401, '/')
    }
  } else {
    res.redirect(401, '/')
  }
}

// Authentication
app.post('/api/user/log-in', (req, res, next) => {
  // Empty/data checks
  if (!req.body.username || !req.body.password) {
    res.json({error: 'All fields must be filled out.'})
  } else if (!Util.validateAlphaNumeric(req.body.username)) {
    res.json({
      error: 'Username or password is wrong.',
    })
  } else if (!Util.validatePassword(req.body.password)) {
    res.json({
      error: 'Username or password is wrong.',
    })
  } else if (!req.body.password || !req.body.username) {
    res.json({error: 'All fields must be filled out.'})
  } else {
    passport.authenticate('local', (err, user, info) => {
      if (err) throw err
      if (!user) res.json({error: 'Username or password is wrong.'})
      else {
        req.logIn(user, (err) => {
          if (err) throw err

          // Put roles in the array
          const userRoles = []
          req.user.Roles.forEach((element) => userRoles.push(element.role_name))

          res.json({
            id: req.user.user_id,
            username: req.user.username,
            roles: userRoles,
          })
        })
      }
    })(req, res, next)
  }
})

// Logging out
app.post('/api/user/log-out', (req, res) => {
  // Destroy the session record from the store
  myStore.destroy(req.sessionID, function () {
    // Destroy the session cookie
    req.session.destroy(function (err) {
      if (!err) {
        res
          .status(200)
          .clearCookie('sessionId', {path: '/'})
          .json({status: 'Session destroyed.'})
      } else {
        res.send("Couldn't destroy the session.")
      }
    })
  })
})

// Validate JWT
app.post('/api/user/token/validate', async (req, res) => {
  try {
    jwt.verify(req.body.token, process.env.JWT_SECRET)

    const unusedtoken = await Users.getUserByToken(req.body.token)
    if (!unusedtoken) {
      res.json({error: 'The link has expired.'})
    } else {
      res.status(200).json({status: 'The link is valid.'})
    }
  } catch (err) {
    console.error(err)
    res.json({error: 'The link has expired.'})
  }
})

app.post('/api/user/password/update', async (req, res) => {
  try {
    jwt.verify(req.body.token, process.env.JWT_SECRET)
  } catch (err) {
    console.error(err)
    console.log('The token has expired.')
    res.json({error: 'The link has expired.'})
  }

  let user = undefined

  if (!req.body.password)
    res.status(200).json({error: 'All fields must be filled out.'})
  else if (!Util.validatePassword(req.body.password)) {
    res.json({
      error: 'Password must be at least 15 characters.',
    })
  } else {
    try {
      const validToken = await Users.getUserByToken(req.body.token)
      if (validToken.user_id !== req.body.id)
        res.json({error: 'The token did not match the user.'})
    } catch (error) {
      throw error
    }

    user = await Users.updatePassword(req.body.id, req.body.password)
    if (!user)
      res.status(200).json({error: "The password couldn't be updated."})
    else res.status(200).json({status: 'Password updated.'})
  }
})

app.post('/api/user/update', async (req, res) => {
  let userByEmail = undefined
  let user = undefined

  if (req.body.flag && req.body.flag === 'set-up user') {
    // Updating the user during the user setup process

    // Check for the valid token
    try {
      const verify = jwt.verify(req.body.token, process.env.JWT_SECRET)
    } catch (error) {
      res.json({error: 'The link has expired.'})
      throw error
    }

    // Empty/data checks
    if (!req.body.email || !req.body.username || !req.body.password) {
      res.json({error: 'All fields must be filled out.'})
    } else if (!Util.validateEmail(req.body.email)) {
      res.json({error: 'Must be a valid email.'})
    } else if (!Util.validateAlphaNumeric(req.body.username)) {
      res.json({
        error: 'Username must be least 3 characters long',
      })
    } else if (!Util.validatePassword(req.body.password)) {
      res.json({
        error: 'Password must be at least 15 characters.',
      })
    } else {
      userByEmail = await Users.getUserByEmail(req.body.email)
      if (!userByEmail) {
        res.json({error: 'The user was not found.'})
      } else {
        user = await Users.updateUser(
          userByEmail.user_id,
          req.body.username,
          req.body.email,
          req.body.password,
          req.body.token,
          null,
          req.body.flag,
        )

        if (!user) {
          res.json({error: "The user couldn't be updated."})
        } else if (user.error) {
          res.send(user.error)
        } else {
          res.status(200).json({status: 'User updated.'})
        }
      }
    }
  } else {
    // updating the token for the user (from password forgot screen)

    // Empty/data checks
    if (!req.body.email) {
      res.json({error: 'All fields must be filled out.'})
    } else if (!Util.validateEmail(req.body.email)) {
      res.json({error: 'Must be a valid email.'})
    } else {
      userByEmail = await Users.getUserByEmail(req.body.email)
      if (!userByEmail) res.json({error: 'The user was not found.'})
      user = await Users.updateUser(
        userByEmail.user_id,
        userByEmail.username,
        userByEmail.email,
        userByEmail.password,
        null,
        null,
        req.body.flag,
      )

      if (user.error) {
        res.send(user)
      } else if (!user) {
        res.json({error: "The user couldn't be updated."})
      } else {
        res.status(200).json({status: 'User updated.'})
      }
    }
  }

  // If SMTP is not set up or broken
  if (user.error) res.send(user)

  if (!user) res.json({error: "The user couldn't be updated."})
  else res.status(200).json({status: 'User updated.'})
})

// Logo retrieval
app.get('/api/logo', async (req, res) => {
  try {
    const logo = await Images.getImagesByType('logo')
    if (!logo) res.json({error: 'The logo was not found.'})
    res.send(logo)
  } catch (err) {
    console.error(err)
  }
})

// Session expiration reset
app.get('/api/renew-session', verifySession, async (req, res) => {
  const user = await Users.getUser(req.session.passport.user)

  // Put roles in the array
  const userRoles = []
  user.Roles.forEach((element) => userRoles.push(element.role_name))

  res
    .status(200)
    .json({id: user.user_id, username: user.username, roles: userRoles})
})

// -------------------------------------------------APIS---------------------------------------------------------------------

const checkApiKey = function (req, res, next) {
  if (req.header('x-api-key') === process.env.APIKEY) {
    next()
  } else {
    res.sendStatus(401)
  }
}

// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!Invitations!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

// Create invitation
app.post('/api/v1/invitations', checkApiKey, async (req, res) => {
  console.log(req.body)
  const data = req.body
  try {
    if (data.invitation_type === 'OOB') {
      console.log('OOB invitation workflow')
      const oob = await Invitations.createOutOfBandInvitation(
        data.contact_id,
        data.handshake_protocol,
        data.alias,
        data.invitation_mode,
        data.accept,
        data.public,
        data.invitation_role,
        data.invitation_label,
        data.invitation_status,
        data.invitation_description,
        data.invitation_active_starting_at,
        data.invitation_active_ending_at,
        data.uses_allowed ? data.uses_allowed : '',
      )

      const connectionInterval = setInterval(async () => {
        const invByOOB = await Invitations.getInvitationByOOBId(
          oob.oobInv.oob_id,
        )

        if (invByOOB) {
          clearInterval(connectionInterval)
          res.status(200).json({
            invitation_url: invByOOB.invitation_url,
            invitation_id: invByOOB.invitation_id,
            contact_id: invByOOB.contact_id,
          })
        }
      }, 1500)
    } else {
      console.log('CV1 invitation workflow')
      const invitation = await Invitations.createInvitation(
        data.contact_id,
        data.alias,
        data.invitation_mode,
        data.accept,
        data.public,
        data.invitation_role,
        data.invitation_label,
        data.invitation_status,
        data.invitation_description,
        data.invitation_active_starting_at,
        data.invitation_active_ending_at,
        data.uses_allowed ? data.uses_allowed : '',
      )

      res.status(200).json({
        invitation_url: invitation.newInv.invitation_url,
        invitation_id: invitation.newInv.invitation_id,
        contact_id: invitation.newInv.contact_id,
      })
    }
  } catch (error) {
    console.error(error)
    res.json({error: 'There was a problem creating an invitation'})
  }
})

// Accept invitation
app.post('/api/v1/invitations/accept', checkApiKey, async (req, res) => {
  console.log('Accepting invitation')

  console.log(req.body)
  const data = req.body

  if (data) {
    try {
      if (data.invitation_url.split('=')[0].split('?')[1] === 'c_i') {
        console.log('Accepting CV1 invitation')
        const invitationMessage = await Invitations.acceptInvitation(
          data.invitation_url,
        )

        if (invitationMessage) {
          // (eldersonar) TODO: save invitation in received_invitations table and then return invitation_id from there
          res
            .status(200)
            .json({success: true, invitation_id: invitationMessage})
        } else {
          console.log(
            'Something went wrong and the connection invitation was not accepted.',
          )
          res.json({
            error:
              'Something went wrong and the connection invitation was not accepted.',
          })
        }
      } else if (data.invitation_url.split('=')[0].split('?')[1] === 'oob') {
        console.log('Accepting OOB invitation')
        const invitationMessage = await Invitations.acceptOutOfBandInvitation(
          data.invitation_url,
        )
        if (invitationMessage) {
          // (eldersonar) TODO: save invitation in received_invitations table and then return invitation_id from there
          res.status(200).json({invitation_id: invitationMessage})
        } else {
          console.log(
            'Something went wrong and the OOB invitation was not accepted.',
          )
          res.json({
            error:
              'Something went wrong and the OOB invitation was not accepted.',
          })
        }
      } else {
        console.log(
          'The protocol is not supported : ' +
            data.invitation_url.split('=')[0].split('?')[1],
        )
        res.json({
          error:
            'The protocol is not supported : ' +
            data.invitation_url.split('=')[0].split('?')[1],
        })
      }
    } catch (error) {
      console.error(error)
      res.json({error})
    }
  } else {
    console.log('Error: no invitation was provided')
    res.json({error: 'Error: no invitation was provided'})
  }
})

// Get all invitations
app.get('/api/v1/invitations', checkApiKey, async (req, res) => {
  console.log('Get all invitations')
  try {
    const invitations = await Invitations.getAll({
      sort: [[[req.query['sort-field'], req.query['sort-direction']]]],
      pageSize: req.query['page-size'],
      currentPage: req.query['current-page'],
      // (eldersonar) The item-count is not doing much even when the valuse is passed
      itemCount: req.query['item-count'],
    })

    if (invitations.count !== 0) {
      res.status(200).json({invitations: invitations})
    } else {
      console.log('No invitations records')
      res.status(200).json({warning: 'No invitations records.'})
    }
  } catch (error) {
    console.error(error)
    res.json({error})
  }
})

// Get invitation by invitation id
app.get('/api/v1/invitations/:id', checkApiKey, async (req, res) => {
  console.log('Get invitation by id')
  console.log(req.params.id)
  try {
    const invitation = await Invitations.getInvitation(req.params.id)

    if (invitation) {
      res.status(200).json({invitation})
    } else {
      console.log('No invitation record found by id')
      res.status(200).json({warning: 'No invitation record found by id.'})
    }
  } catch (error) {
    console.error(error)
    res.json({error})
  }
})

// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!Invitations!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!Credentials!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

// Issue credential
app.post('/api/v1/credentials', checkApiKey, async (req, res) => {
  console.log(req.body)
  const data = req.body

  try {
    const invitationId = data.invitation_id || null
    const contactId = data.contact_id || ''

    // (eldersonar) Make sure that the invitation id is either a number or a string
    if (typeof invitationId === 'number' || invitationId === null) {
      // (eldersonar) Make sure that the invitation id is either a number or a string
      if (typeof contactId !== 'string') {
        throw {error: 'Contact id must be type of string'}
      } else {
        if (invitationId === null && contactId === '') {
          throw 'MISSING_IDENTIFIER'
        }

        const schemaId = data.schema_id
        const attributes = data.attributes

        console.log('')
        console.log(
          '_____________Credential flow triggered - add request_____________',
        )
        console.log('')

        let result = null

        result = await IssuanceRequests.addRequest(
          contactId,
          invitationId,
          schemaId,
          attributes,
        )

        if (result && result.error) {
          throw result
        }

        // (mikekebert) After we record a new issuance request, we need to check to see if there is an active connection
        // for either this invitationId and/or this contactId (whichever was provided);
        // If there is, we can issue the credential right away
        console.log('')
        console.log(
          '_____________Credential flow triggered - process requests_____________',
        )
        console.log('')
        result = await IssuanceRequests.processRequests(contactId, invitationId)

        if (result && result.error) {
          throw result
        }
        if (result && result.warning) {
          res.status(200).json({warning: result.warning})
        } else {
          res.status(200).json({success: 'Credential was offered'})
        }
      }
    } else {
      throw {error: 'Invitation id must be type of integer or null'}
    }
  } catch (error) {
    // TODO: replace with the custom extended message provided by Mike Ebert
    console.error(error)
    if (error === 'MISSING_IDENTIFIER') {
      res.json({error: "contact_id and invitation_id can't both be null"})
    } else if (error) {
      // (eledersonar) TODO: find the best code for default in case we need one
      let errorStatus = 500
      if (!error.code || error.code < 100) {
        // Add a custom error code
        errorStatus = 500
      } else {
        // Handle error code coming from a broken adminAPI call
        errorStatus = error.code
        delete error.code
      }
      res.status(errorStatus).json(error)
    } else {
      res.json({
        error:
          'The credential could not be issued. Please, check your inputs and DID.',
      })
    }
  }
})

// Get all credentials
app.get('/api/v1/credentials', checkApiKey, async (req, res) => {
  console.log('Get all credentials')
  try {
    const credentials = await Credentials.getAll()

    if (credentials) {
      res.status(200).json({credentials: credentials})
    } else {
      console.log('No credentials records')
      res.status(200).json({warning: 'No credentials records.'})
    }
  } catch (error) {
    console.error(error)
    res.json({error})
  }
})

// Get credential by credential exchange id
app.get('/api/v1/credentials/:id', checkApiKey, async (req, res) => {
  console.log('Get credential by id')
  console.log(req.params.id)
  try {
    const credential = await Credentials.getCredential(req.params.id)

    if (credential) {
      res.status(200).json({credential})
    } else {
      console.log('No credential record found by id')
      res.status(200).json({warning: 'No credential record found by id.'})
    }
  } catch (error) {
    console.error(error)
    res.json({error})
  }
})

// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!Credentials!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!Verifications!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

// Create verification
app.post('/api/v1/verifications', checkApiKey, async (req, res) => {
  const data = req.body

  try {
    const invitationId = data.invitation_id || null
    const contactId = data.contact_id || ''

    // (eldersonar) Make sure that the invitation id is either a number or a string
    if (typeof invitationId === 'number' || invitationId === null) {
      // (eldersonar) Make sure that the invitation id is either a number or a string
      if (typeof contactId !== 'string') {
        throw {error: 'Contact id must be type of string'}
      } else {
        if (invitationId === null && contactId === '') {
          throw 'MISSING_IDENTIFIER'
        }

        console.log('')
        console.log(
          '_____________Verification flow triggered - verify_____________',
        )
        console.log('')

        const verification = await Verifications.verify({
          invitation_id: invitationId,
          contact_id: contactId,
          schemas: data.schemas,
          timeout: data.timeout,
          rule: data.rule,
        })

        if (verification && verification.error) {
          throw verification
        }
        if (verification && verification.warning) {
          res.status(200).json({warning: verification.warning})
        } else {
          res.status(200).send(verification)
        }
      }
    } else {
      throw {error: 'Invitation id must be type of integer or null'}
    }
  } catch (error) {
    // TODO: replace with the custom extended message provided by Mike Ebert
    console.error(error)
    if (error === 'MISSING_IDENTIFIER') {
      res.json({error: "contact_id and invitation_id can't both be null"})
    } else if (error) {
      // (eledersonar) TODO: find the best code for default in case we need one
      let errorStatus = 500
      if (!error.code || error.code < 100) {
        // Add a custom error code
        errorStatus = 500
      } else {
        // Handle error code coming from a broken adminAPI call
        errorStatus = error.code
        delete error.code
      }
      res.status(errorStatus).json(error)
    } else {
      res.json({
        error: 'Unexpected error occurred',
      })
    }
  }
})

// Get verification by verification id
app.get('/api/v1/verifications/:id', checkApiKey, async (req, res) => {
  try {
    console.log('')
    console.log(
      '_____________Verification flow triggered - retrieve_____________',
    )
    console.log('')
    const verification = await Verifications.retrieve(req.params.id)

    res.status(200).json(verification)
  } catch (error) {
    console.error(error)
    res.json({error: 'There was a problem retrieving a verification'})
  }
})
// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!Verifications!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

// -------------------------------------------------APIS---------------------------------------------------------------------

app.use('/', (req, res) => {
  console.log('Request outside of normal paths', req.url)
  console.log(req.body)
  res.status(404).send()
})
