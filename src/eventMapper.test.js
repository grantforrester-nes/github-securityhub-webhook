const { mapEventToCommand } = require('./eventMapper')
const { BatchImportFindingsCommand, BatchUpdateFindingsCommand } = require('@aws-sdk/client-securityhub')
const config = require('./config')

jest.mock('./config', () => {
  return {
    aws_region: 'mock-region',
    aws_account_id: 'mock-account-id',
    generator_id: 'mock-generator-id'
  }
})

describe('eventMapper', () => {
  describe('mapEventToCommand', () => {
    const now = new Date()

    beforeEach(() => {
      jest.setSystemTime(now)
    })

    it('should return import findings command on create event', async () => {
      // Given
      const mockEvent = {
        action: 'create',
        alert: {
          id: 'mock-alert-id',
          created_at: '2011-10-05T14:48:00.000Z',
          affected_package_name: 'mock-package-name'
        }
      }

      // When
      const result = await mapEventToCommand(mockEvent)

      // Then
      expect(result).toBeInstanceOf(BatchImportFindingsCommand)
      expect(result.input).toEqual([{
        SchemaVersion: '2018-10-08',
        AwsAccountId: config.aws_account_id,
        CreatedAt: mockEvent.alert.created_at,
        UpdatedAt: now.toISOString(),
        GeneratorId: config.generator_id,
        Id: mockEvent.alert.id,
        ProductArn: `arn:aws:securityhub:${config.aws_region}:${config.aws_account_id}:product/${config.aws_account_id}/default`,
        Title: mockEvent.alert.affected_package_name,
        Description: mockEvent.alert.affected_package_name
      }])
    })

    it('should return update findings command on dismiss event', async () => {
      // Given
      const mockEvent = { action: 'dismiss', alert: { id: 'mock-alert-id' } }

      // When
      const result = await mapEventToCommand(mockEvent)

      // Then
      expect(result).toBeInstanceOf(BatchUpdateFindingsCommand)
      expect(result.input).toEqual({
        FindingIdentifiers: [
          {
            Id: mockEvent.alert.id,
            ProductArn: `arn:aws:securityhub:${config.aws_region}:${config.aws_account_id}:product/${config.aws_account_id}/default`
          }
        ],
        Note: { Text: 'Finding suppressed', UpdatedBy: config.generator_id },
        Workflow: { Status: 'SUPPRESSED' }
      }
      )
    })

    it('should return update findings command on resolve event', async () => {
      // Given
      const mockEvent = { action: 'resolve', alert: { id: 'mock-alert-id' } }

      // When
      const result = await mapEventToCommand(mockEvent)

      // Then
      expect(result).toBeInstanceOf(BatchUpdateFindingsCommand)
      expect(result.input).toEqual({
        FindingIdentifiers: [
          {
            Id: mockEvent.alert.id,
            ProductArn: `arn:aws:securityhub:${config.aws_region}:${config.aws_account_id}:product/${config.aws_account_id}/default`
          }
        ],
        Note: { Text: 'Finding resolved', UpdatedBy: config.generator_id },
        Workflow: { Status: 'RESOLVED' }
      }
      )
    })

    it('should throw error on invalid event', async () => {
      // Given
      const mockEvent = { id: 'invalid-event' }

      // Then
      expect(() => mapEventToCommand(mockEvent)).toThrowError()
    })
  })
})
