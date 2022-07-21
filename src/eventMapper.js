const { BatchImportFindingsCommand, BatchUpdateFindingsCommand } = require('@aws-sdk/client-securityhub')
const config = require('./config')

/*
findings = [{
    'SchemaVersion': '2018-10-08',
    'AwsAccountId': aws_account_id,
    'CreatedAt': datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
    'UpdatedAt': datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
    'GeneratorId': 'github',
    'Id': str(payload['alert']['id']),
    'ProductArn': 'arn:aws:securityhub:%s:%s:product/%s/default' % (aws_region, aws_account_id, aws_account_id),
    'Title': '%s %s' % (payload['alert']['affected_package_name'], payload['alert']['fixed_in']),
    'Description': payload['alert']['affected_package_name'],
    'Resources': [{
      'Type': 'Other',
      'Id': '%s/%s/%s' % (repo_name, package_name, cve_id),
      'Region': aws_region,
      'Details': {
        'Other': {
          'github.com/repository.name': payload['repository']['name'],
          'github.com/repository.owner': payload['repository']['owner']['login']
        }
      }
    }]
  }]
 */

function toAsff (event, config) {
  return [{
    SchemaVersion: '2018-10-08',
    AwsAccountId: config.aws_account_id,
    CreatedAt: event.alert.created_at,
    UpdatedAt: new Date().toISOString(),
    GeneratorId: config.generator_id,
    Id: event.alert.id,
    ProductArn: formatProductArn(config),
    Title: event.alert.affected_package_name,
    Description: event.alert.affected_package_name
  }]
}

function formatProductArn (config) {
  return `arn:aws:securityhub:${config.aws_region}:${config.aws_account_id}:product/${config.aws_account_id}/default`
}

const actionMap = {
  dismiss: {
    text: 'Finding suppressed',
    status: 'SUPPRESSED'
  },
  resolve: {
    text: 'Finding resolved',
    status: 'RESOLVED'
  }
}

function mapEventToCommand (event) {
  let command
  switch (event.action) {
    case 'create': command = new BatchImportFindingsCommand(toAsff(event, config))
      break
    case 'dismiss': command = new BatchUpdateFindingsCommand(toUpdate(event, config))
      break
    case 'resolve': command = new BatchUpdateFindingsCommand(toUpdate(event, config))
      break
    default: throw new Error('Invalid event')
  }

  return command
}

function toUpdate (event) {
  return {
    FindingIdentifiers: [
      {
        Id: event.alert.id,
        ProductArn: formatProductArn(config)
      }
    ],
    Note: {
      Text: actionMap[event.action].text,
      UpdatedBy: config.generator_id
    },
    Workflow: {
      Status: actionMap[event.action].status
    }
  }
}

module.exports = {
  mapEventToCommand
}
