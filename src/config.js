module.exports = {
  aws_region: process.env.AWS_REGION || 'eu-west-2',
  aws_account_id: process.env.AWS_ACCOUNT_ID,
  generator_id: process.env.GENERATOR_ID || 'github-webhook'
}
