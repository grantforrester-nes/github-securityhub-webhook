const { SecurityHubClient } = require('@aws-sdk/client-securityhub')
const { mapEventToCommand } = require('./eventMapper')
const config = require('./config')

module.exports = async (event) => {
  console.log('New event received')
  const response = {}

  try {
    const client = new SecurityHubClient({ region: config.aws_region })
    const command = mapEventToCommand(event)
    const result = await client.send(command)
    // TODO Anything useful from result?
    console.log(result)

    response.statusCode = 202
  } catch (err) {
    // TODO better error handling
    console.log(err)
    response.statusCode = 400
  }
  return response
}
