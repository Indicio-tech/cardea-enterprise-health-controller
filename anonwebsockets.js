const server = require('./index.js').server
const ControllerError = require('./errors.js')
const WebSocket = require('ws')

awss = new WebSocket.Server({noServer: true})
let connectionIDWebSocket = []

const checkWebsocketID = (connectionID) => {
  console.log(connectionID)
  console.log(connectionIDWebSocket)
  console.log(connectionID in connectionIDWebSocket)
  console.log("Check to see if we have this anonymous websocket connection")
  return connectionID in connectionIDWebSocket
}

// Send a message to all connected clients
const sendMessageToAll = (context, type, data = {}) => {
  try {
    console.log(
      `Sending Message to all anon websocket clients of type: ${type}`,
    )

    awss.clients.forEach(function each(client) {
      if (client.type != 'anon') {
        return
      }
      if (client.readyState === WebSocket.OPEN) {
        console.log('Sending Message to Client')
        client.send(JSON.stringify({context, type, data}))
      } else {
        console.log('Client Not Ready')
      }
    })
  } catch (error) {
    console.error('Error Sending Message to All Clients')
    throw error
  }
}

const sendMessageToConnectionId = (connection_id, context, type, data = {}) => {
  let ws = connectionIDWebSocket[connection_id]

  console.log(`Sending Message to anon websocket client of type: ${type}`)
  try {
    ws.send(JSON.stringify({context, type, data}))
  } catch (error) {
    console.error(error)
    throw error
  }
}

// (JamesKEbert) TODO: Add a connection timeout to gracefully exit versus nginx configuration closing abrubtly
awss.on('connection', (ws, req) => {
  console.log('New Anon Websocket Connection')
  ws.connection_ids = []

  // store the connection_ids assoicated with the connection

  ws.on('message', (message) => {
    try {
      const parsedMessage = JSON.parse(message)
      console.log('New Anon Websocket Message:', parsedMessage)

      messageHandler(
        ws,
        parsedMessage.context,
        parsedMessage.type,
        parsedMessage.data,
      )
    } catch (error) {
      console.error(error)
    }
  })

  ws.on('close', (code, reason) => {
    console.log('Anon Websocket Connection Closed', code, reason)

    ws.connection_ids.forEach(
      (connection_id) => delete connectionIDWebSocket[connection_id],
    )
  })

  ws.on('ping', (data) => {
    console.log('Ping')
  })
  ws.on('pong', (data) => {
    console.log('Pong')
  })
})

// Send an outbound message to a websocket client
const sendMessage = (ws, context, type, data = {}) => {
  console.log(`Sending Message to anon websocket client of type: ${type}`)
  try {
    ws.send(JSON.stringify({context, type, data}))
  } catch (error) {
    console.error(error)
    throw error
  }
}

// Send an Error Message to a websocket client
const sendErrorMessage = (ws, errorCode, errorReason) => {
  try {
    console.log('Sending Error Message')

    sendMessage(ws, 'ERROR', 'SERVER_ERROR', {errorCode, errorReason})
  } catch (error) {
    console.error('Error Sending Error Message to Client')
    console.error(error)
  }
}

// Handle inbound messages
const messageHandler = async (ws, context, type, data = {}) => {
  try {
    console.log(`New Message with context: '${context}' and type: '${type}'`)
    switch (context) {
      case 'INVITATIONS':
        switch (type) {
          case 'CREATE_SINGLE_USE':
            var invitation
            invitation = await Invitations.createSingleUseInvitation()

            ws.connection_ids.push(invitation.connection_id)
            connectionIDWebSocket[invitation.connection_id] = ws

            sendMessage(ws, 'INVITATIONS', 'INVITATION', {
              invitation_record: invitation,
            })
            break

          default:
            console.error(`Unrecognized Message Type: ${type}`)
            sendErrorMessage(ws, 1, 'Unrecognized Message Type')
            break
        }
        break

      default:
        console.error(`Unrecognized Message Context: ${context}`)
        sendErrorMessage(ws, 1, 'Unrecognized Message Context')
        break
    }
  } catch (error) {
    if (error instanceof ControllerError) {
      console.error('Controller Error in Message Handling', error)
      sendErrorMessage(ws, error.code, error.reason)
    } else {
      console.error('Error In Anon Websocket Message Handling', error)
      sendErrorMessage(ws, 0, 'Internal Error')
    }
  }
}

module.exports = {
  checkWebsocketID,
  sendMessageToAll,
  sendMessageToConnectionId,
  awss,
}

const Invitations = require('./agentLogic/invitations')
