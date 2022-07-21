const webhook = require('./webhook')
const {
  SecurityHubClient
} = require('@aws-sdk/client-securityhub')
const { mapEventToCommand } = require('./eventMapper')

jest.mock('./eventMapper')
jest.mock('./config', () => {
  return {
    aws_region: 'mock-region'
  }
})

describe('webhook', () => {
  let log, send

  beforeEach(() => {
    log = jest.spyOn(console, 'log').mockImplementation()
    send = jest.spyOn(SecurityHubClient.prototype, 'send').mockImplementation()
  })

  it('should return success', async () => {
    // Given
    const mockEvent = { id: 'mockEvent' }
    const mockCommand = { id: 'mockCommand' }
    mapEventToCommand.mockReturnValue(mockCommand)

    // When
    const result = await webhook(mockEvent)

    // Then
    expect(send).toHaveBeenCalledWith(mockCommand)
    expect(result).toEqual({ statusCode: 202 })
  })

  it('should return an error if invalid event', async () => {
    // Given
    const mockEvent = { id: 'mockEvent' }
    const mockError = new Error('mockError')
    mapEventToCommand.mockImplementation(() => {
      throw mockError
    })

    // When
    const result = await webhook(mockEvent)

    // Then
    expect(result).toEqual({ statusCode: 400 })
    expect(log).toHaveBeenCalledWith(mockError)
  })

  it('should return an error if send fails', async () => {
    // Given
    const mockEvent = { id: 'mockEvent' }
    const mockError = new Error('mockError')
    const mockCommand = { id: 'mockCommand' }
    mapEventToCommand.mockReturnValue(mockCommand)
    send.mockImplementation(() => {
      throw mockError
    })

    // When
    const result = await webhook(mockEvent)

    // Then
    expect(send).toHaveBeenCalledWith(mockCommand)
    expect(result).toEqual({ statusCode: 400 })
    expect(log).toHaveBeenCalledWith(mockError)
  })
})
