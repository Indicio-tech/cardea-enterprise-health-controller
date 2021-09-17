const ControllerError = require('../errors.js')

const AdminAPI = require('../adminAPI')
const Websockets = require('../websockets.js')
const AnonWebsockets = require('../anonwebsockets.js')

const requestPresentation = async (connectionID) => {
  console.log(`Requesting Presentation from Connection: ${connectionID}`)

  AdminAPI.Presentations.requestPresentation(
    connectionID,
    ['address'],
    'TaDe8aSZMxoEU4GZDm9AKK:2:Validated_Email:1.0',
    'Requesting Presentation',
    false,
  )
}

const adminMessage = async (message) => {
  console.log('Received Presentations Message', message)

  if (message.state === 'verified') {
    if (AnonWebsockets.checkWebsocketID(message.connection_id)) {
      console.log (message.presentation.requested_proof.revealed_attrs.address)
      AnonWebsockets.sendMessageToConnectionId(message.connection_id, 'PRESENTATIONS', 'VERIFIED', {
        address: message.presentation.requested_proof.revealed_attrs.address,
      })
    }
    else {
      console.log (message.presentation.requested_proof.revealed_attrs.address)
      Websockets.sendMessageToAll('PRESENTATIONS', 'VERIFIED', {
        connection_id: message.connection_id,
      })
    }
  }
}

module.exports = {
  adminMessage,
  requestPresentation,
}
